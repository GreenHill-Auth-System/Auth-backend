
import base64
import hashlib
import logging
import os
import secrets
from rest_framework.decorators import throttle_classes
from .throttles import LoginRateThrottle
from .audit import log_event

from django.conf import settings
from django.contrib.auth import (
    authenticate,
    get_user_model,
    login,
    logout,
)
from django.core.exceptions import DisallowedHost
from django.http import HttpResponse, JsonResponse
from django.middleware.csrf import get_token
from django.shortcuts import get_object_or_404, redirect
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.csrf import ensure_csrf_cookie

from drf_spectacular.utils import (
    OpenApiResponse,
    extend_schema,
    inline_serializer,
)
from rest_framework import serializers
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import AllowAny, IsAuthenticated

from google.auth.transport import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow

from oauth2_provider.models import get_application_model

from authentication.access import get_user_access
from authentication.avatar_tokens import avatar_path, avatar_user_from_token
from authentication.domain_guard import (
    GREENHILL_EMAIL_HINT,
    is_greenhill_email,
    is_valid_greenhill_email,
)
from authentication.google_flow import forget_flow, read_flow, remember_flow
from authentication.models import UserProfile, UserSession, UserSettings
from authentication.sessions import (
    active_sessions,
    revoke_all_sessions,
    revoke_other_sessions,
    revoke_session,
    revoke_session_by_key,
    serialize_session,
    track_session,
)
from authentication.tokens import revoke_user_tokens
from authentication.users import (
    find_user_by_email,
    google_claims_are_trustworthy,
    resolve_google_user,
)

if os.getenv("DJANGO_ENV") == "development":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


logger = logging.getLogger(__name__)


GOOGLE_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]

REQUIRED_CREDENTIALS_MESSAGE = (
    "Please enter your Greenhill Workspace credentials."
)

GREENHILL_EMAIL_REQUIRED_MESSAGE = (
    "Please use your Greenhill Academy work email address to sign in."
)

INVALID_CREDENTIALS_MESSAGE = (
    "Incorrect email or password. "
    "Please check your credentials and try again."
)

GREENHILL_EMAIL_FORMAT_MESSAGE = (
    "That does not look like a GreenHill staff email address. "
    + GREENHILL_EMAIL_HINT
)

# Session key holding the URL to return to after a successful sign-in. This is
# how /o/authorize/ survives the trip out to Google and back.
POST_LOGIN_REDIRECT_KEY = "post_login_redirect"

DEFAULT_LANDING_PATH = "/workspaces?login=success"


# ---------------------------------------------------------------------------
# Documentation-only serializers
#
# These exist purely so drf-spectacular can describe the JSON these views
# return. Nothing validates through them; the views build plain dicts. Having
# them here is what stops drf_spectacular.W002 ("unable to guess serializer")
# from being emitted for every APIView-style function view in this module.
# ---------------------------------------------------------------------------

SIGN_OUT_RESPONSE = inline_serializer(
    name="SignOutResponse",
    fields={
        "authenticated": serializers.BooleanField(),
        "message": serializers.CharField(),
        "sessions_revoked": serializers.IntegerField(),
        "access_tokens_revoked": serializers.IntegerField(),
        "refresh_tokens_revoked": serializers.IntegerField(),
    },
)

SESSION_ITEM = inline_serializer(
    name="SessionItem",
    fields={
        "id": serializers.IntegerField(),
        "ip_address": serializers.CharField(allow_null=True),
        "user_agent": serializers.CharField(allow_blank=True),
        "created_at": serializers.DateTimeField(),
        "last_seen_at": serializers.DateTimeField(),
        "is_current": serializers.BooleanField(),
    },
)

SESSION_LIST_RESPONSE = inline_serializer(
    name="SessionListResponse",
    fields={
        "count": serializers.IntegerField(),
        "sessions": serializers.ListField(child=SESSION_ITEM),
    },
)

SESSION_REVOKE_RESPONSE = inline_serializer(
    name="SessionRevokeResponse",
    fields={
        "revoked": serializers.BooleanField(),
        "session_id": serializers.IntegerField(),
    },
)

SESSION_REVOKE_OTHERS_RESPONSE = inline_serializer(
    name="SessionRevokeOthersResponse",
    fields={
        "revoked": serializers.BooleanField(),
        "sessions_revoked": serializers.IntegerField(),
    },
)

SESSION_REVOKE_ALL_RESPONSE = inline_serializer(
    name="SessionRevokeAllResponse",
    fields={
        "authenticated": serializers.BooleanField(),
        "revoked": serializers.BooleanField(),
        "sessions_revoked": serializers.IntegerField(),
        "current_session_key_present": serializers.BooleanField(),
    },
)


def get_frontend_url():
    return os.getenv(
        "FRONTEND_URL",
        "http://localhost:5173",
    ).rstrip("/")


def _mask_email(email):
    """``ab***@example.com`` -- enough to identify an account in a log line.

    Sign-in rejections are logged so an administrator can tell "wrong Google
    account" from "deactivated account", but a log is not the place to keep a
    complete staff address book.
    """
    local, _, domain = (email or "").partition("@")
    if not domain:
        return "***"
    return f"{local[:2]}***@{domain}"


def _google_failure(request, reason):
    """Send a failed Google sign-in back to a page that can explain it.

    The pending `next` target is deliberately left in the session: a retry
    should resume the authorization it interrupted, not silently drop the user
    into the workspace picker.

    The handshake cookie is cleared on every failure so a vetoed attempt cannot
    leave a still-valid state lying around in this browser.
    """
    return forget_flow(redirect(f"{get_frontend_url()}/?error={reason}"))


def _request_host(request):
    """This request's host, even when Django does not recognise it.

    ``request.get_host()`` raises ``DisallowedHost`` for any host missing from
    ``ALLOWED_HOSTS``. Deciding whether ``next`` points back at us must never be
    the thing that turns a sign-in request into a 400, so a host Django does not
    trust is read from the raw header instead: it is only ever compared against
    the target, never trusted for anything else, and a request with a forged
    ``Host`` can at worst redirect the forger to their own server.
    """
    try:
        return request.get_host()
    except DisallowedHost:
        return request.META.get("HTTP_HOST") or request.META.get("SERVER_NAME", "")


def _is_safe_redirect(target, request):
    """True when ``target`` is a path on this very host.

    A `next` parameter is attacker-controlled. Without this check the sign-in
    flow becomes an open redirect, which is how phishing pages harvest
    credentials.
    """
    if not target:
        return False

    host = _request_host(request)
    if not host:
        return False

    return url_has_allowed_host_and_scheme(
        target,
        allowed_hosts={host},
        require_https=request.is_secure(),
    )


def remember_post_login_redirect(request):
    """Store a safe `next` target so the OIDC round trip can resume."""
    target = request.GET.get("next") or request.POST.get("next")
    if not _is_safe_redirect(target, request):
        return ""

    request.session[POST_LOGIN_REDIRECT_KEY] = target
    return target


def consume_post_login_redirect(request):
    """Pop the stored `next` target, or return the default landing page.

    Session data survives ``login()`` (it cycles the key but keeps the data),
    so the target stored before the Google round trip is still here.
    """
    return request.session.pop(
        POST_LOGIN_REDIRECT_KEY,
        "",
    ) or f"{get_frontend_url()}{DEFAULT_LANDING_PATH}"


def _session_user(request):
    """The account behind this browser session, without DRF authentication.

    ``sign_out`` is reachable without DRF authentication so a cross-origin
    ``fetch`` from the three frontends is not rejected by CSRF checks, which
    means ``request.user`` is anonymous there. The session is what identifies
    the account.
    """
    user_id = request.session.get("_auth_user_id")
    if not user_id:
        return None

    try:
        return get_user_model().objects.filter(pk=user_id).first()
    except (TypeError, ValueError):
        return None


def _end_session(request, *, everywhere=False):
    """Tear down the IdP session and the credentials derived from it.

    Order matters:

    1. resolve the account *before* ``logout()`` flushes the session,
    2. destroy the inventoried session row(s),
    3. revoke the OAuth tokens. A relying party already holding an access
       token would otherwise keep working until it expired, which is exactly
       the thing a central sign-out must prevent,
    4. finally flush the session.
    """
    user = _session_user(request)
    session_key = request.session.session_key

    tokens = {"access_tokens": 0, "refresh_tokens": 0}
    sessions_revoked = 0

    if user is not None:
        if everywhere:
            sessions_revoked = revoke_all_sessions(user)
        elif session_key and revoke_session_by_key(session_key, user=user):
            sessions_revoked = 1

        tokens = revoke_user_tokens(user)

    logout(request)

    return {
        "sessions_revoked": sessions_revoked,
        "access_tokens_revoked": tokens["access_tokens"],
        "refresh_tokens_revoked": tokens["refresh_tokens"],
    }


def generate_code_verifier():
    return secrets.token_urlsafe(64)


def generate_code_challenge(code_verifier):
    digest = hashlib.sha256(
        code_verifier.encode("ascii")
    ).digest()

    return base64.urlsafe_b64encode(
        digest
    ).rstrip(b"=").decode("ascii")


@extend_schema(
    summary="Start Google OAuth login",
    description=(
        "Starts the Google OAuth 2.0 / OpenID Connect authentication flow."
    ),
    responses={
        302: OpenApiResponse(
            description="Redirects the user to Google."
        ),
    },
)
@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def google_login(request):
    # A `next` target is captured first so that a signed-in browser can be
    # sent straight back to it, and so a fresh sign-in resumes the OIDC
    # request that started this detour.
    remember_post_login_redirect(request)

    already_signed_in = _session_user(request) is not None
    if already_signed_in and request.session.get(POST_LOGIN_REDIRECT_KEY):
        # Single sign-on: the IdP session already answers "who is this?",
        # so there is no reason to prompt Google again.
        return redirect(consume_post_login_redirect(request))

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=GOOGLE_SCOPES,
    )

    flow.redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")

    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)

    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="select_account",
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )

    request.session["google_oauth_state"] = state
    request.session["google_code_verifier"] = code_verifier

    # The session cookie is issued here and must come back after a detour
    # through accounts.google.com. Some browsers will not keep a SameSite=None
    # cookie across that chain, so the handshake is also carried in a signed
    # cookie scoped to the callback. See authentication/google_flow.py.
    response = redirect(authorization_url)
    return remember_flow(
        request,
        response,
        state=state,
        code_verifier=code_verifier,
    )


@extend_schema(
    summary="Google OAuth callback",
    description=(
        "Verifies the Google identity, checks the GreenHill email domain, "
        "creates or retrieves the local user, and establishes a session."
    ),
    responses={
        302: OpenApiResponse(
            description=(
                "Redirects to the frontend workspace selector, or back to "
                "the sign-in page with a ?error= reason code."
            )
        ),
    },
)
@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def google_callback(request):
    """Finish a Google sign-in, and always end up somewhere a human can read.

    Every failure used to return a bare 400 text page. To a user that is
    indistinguishable from a broken site, and it explains nothing -- the browser
    simply stopped on a URL that reads ``accounts.google.com`` in their history
    and then showed a line of plain text. Each failure now sends the browser
    back to the sign-in page with a ``?error=`` code the frontend turns into a
    sentence, which is the only way the person who was rejected can act on it.
    """
    state = request.session.get("google_oauth_state")
    code_verifier = request.session.get("google_code_verifier")

    if not state or not code_verifier:
        # Fall back to the signed handshake cookie before giving up. A missing
        # session here usually means the browser dropped the session cookie on
        # the way back from Google, not that this sign-in was never started.
        cookie_state, cookie_verifier = read_flow(request)
        if cookie_state and cookie_verifier:
            logger.info(
                "google callback: recovered handshake from signed cookie "
                "(session cookie did not survive the Google round trip)"
            )
            state = cookie_state
            code_verifier = cookie_verifier

    if not state:
        # The state lived in this browser's session. It is gone if the session
        # cookie never made the round trip -- usually because this callback was
        # opened in a different browser, a private window, or after the cookie
        # was cleared. Nothing was authenticated, so a retry is safe.
        logger.warning("google callback: no OAuth state in session")
        return _google_failure(request, "oauth_state_missing")

    if not code_verifier:
        logger.warning("google callback: no PKCE verifier in session")
        return _google_failure(request, "oauth_state_missing")

    if request.GET.get("state") != state:
        logger.warning("google callback: state mismatch")
        return _google_failure(request, "oauth_state_missing")

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=GOOGLE_SCOPES,
        state=state,
    )

    flow.redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")

    try:
        flow.fetch_token(
            authorization_response=request.build_absolute_uri(),
            code_verifier=code_verifier,
        )
    except Exception as exc:
        # Never swallowed silently: a misconfigured redirect URI or client
        # secret only ever shows up here, and the message names the cause.
        logger.warning("google token exchange failed: %s", exc)
        return _google_failure(request, "oauth_token_exchange_failed")

    credentials = flow.credentials

    try:
        google_user = id_token.verify_oauth2_token(
            credentials.id_token,
            requests.Request(),
            os.getenv("GOOGLE_CLIENT_ID"),
        )
    except Exception as exc:
        logger.warning("google id token verification failed: %s", exc)
        return _google_failure(request, "oauth_id_token_invalid")

    email = (google_user.get("email") or "").strip().lower()
    name = google_user.get("name") or ""

    if not is_greenhill_email(email):
        # The browser only ever learns the reason code, so the log is the only
        # place an administrator can find out *which* account was turned away.
        logger.warning(
            "google sign-in rejected for non-GreenHill address %s",
            _mask_email(email),
        )
        return _google_failure(request, "greenhill_account_required")

    # Google must assert that it has verified this address, and a Workspace
    # account must belong to GreenHill's hosted domain. Checking only the email
    # suffix would trust an unverified address asserted by a Workspace admin.
    claims_ok, claim_error = google_claims_are_trustworthy(google_user)
    if not claims_ok:
        logger.warning(
            "google sign-in rejected for %s: %s (hd=%r verified=%r)",
            _mask_email(email),
            claim_error,
            google_user.get("hd"),
            google_user.get("email_verified"),
        )
        return _google_failure(request, claim_error)

    access = get_user_access(email)

    # Resolve the identity before creating anything: a Google subject that is
    # already bound to somebody else must never leave a stray account behind.
    try:
        user, _created = resolve_google_user(google_user)
    except ValueError as exc:
        logger.warning(
            "google sign-in conflict for %s: %s",
            _mask_email(email),
            exc,
        )
        return _google_failure(request, "identity_conflict")

    if not user.is_active:
        logger.warning(
            "google sign-in refused for inactive account %s",
            _mask_email(email),
        )
        return _google_failure(request, "account_inactive")

    login(request, user)

    # `login()` cycles the session key, so the inventory row can only be
    # created now: a row keyed on the pre-login key would never be found again.
    track_session(request, user, force=True)

    authenticated_user = {
        "email": email,
        "name": name or user.get_full_name() or user.email,
        "role": access["role"],
        "authorized_systems": access["authorized_systems"],
    }

    request.session["authenticated_user"] = authenticated_user

    # Clear the one-time OAuth state and PKCE verifier after success.
    request.session.pop("google_oauth_state", None)
    request.session.pop("google_code_verifier", None)

    # If this sign-in was a detour from /o/authorize/, go back there so the
    # relying party gets its authorization code instead of a stranded browser.
    return forget_flow(redirect(consume_post_login_redirect(request)))


@extend_schema(
    summary="Manual login",
    description=(
        "Authenticates a GreenHill user using their email and application password."
    ),
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string",
                    "format": "email",
                },
                "password": {
                    "type": "string",
                    "format": "password",
                },
                "remember": {
                    "type": "boolean",
                },
            },
            "required": ["email", "password"],
        }
    },
    responses={
        200: OpenApiResponse(
            description="Authentication successful."
        ),
        400: OpenApiResponse(
            description="Invalid or incomplete login request."
        ),
        401: OpenApiResponse(
            description="Invalid credentials."
        ),
        403: OpenApiResponse(
            description="The email is not a GreenHill Academy work email."
        ),
    },
)
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([LoginRateThrottle])
def manual_login(request):
    data = request.data

    email = str(data.get("email") or "").strip().lower()
    password = str(data.get("password") or "")
    remember = data.get("remember", False)
    if not email or not password:
        return JsonResponse(
            {
                "authenticated": False,
                "error": "required_fields",
                "message": REQUIRED_CREDENTIALS_MESSAGE,
                "fields": {
                    "email": not bool(email),
                    "password": not bool(password),
                },
            },
            status=400,
        )

    if not is_greenhill_email(email):
        return JsonResponse(
            {
                "authenticated": False,
                "error": "greenhill_email_required",
                "message": GREENHILL_EMAIL_REQUIRED_MESSAGE,
                "fields": {
                    "email": True,
                    "password": False,
                },
            },
            status=403,
        )

    # The suffix proves the domain; this proves the address is one this
    # organisation could actually have issued. Sign-in is the only place a
    # person types it, so a malformed address is caught here rather than
    # silently failing to match an AllowedEmail row later.
    if not is_valid_greenhill_email(email):
        return JsonResponse(
            {
                "authenticated": False,
                "error": "greenhill_email_format",
                "message": GREENHILL_EMAIL_FORMAT_MESSAGE,
                "fields": {
                    "email": True,
                    "password": False,
                },
            },
            status=403,
        )

    # Django authenticates by username, but email is our identity key. Resolve
    # the account first so the match is case-insensitive on email instead of
    # depending on the username happening to equal the address.
    account = find_user_by_email(email)

    user = None
    if account is not None:
        user = authenticate(
            request,
            username=account.get_username(),
            password=password,
        )

    if user is None or not user.is_active:
        log_event(request, "login_fail", email)
        return JsonResponse(
            {
                "authenticated": False,
                "error": "invalid_credentials",
                "message": INVALID_CREDENTIALS_MESSAGE,
                "fields": {
                    "email": True,
                    "password": True,
                },
            },
            status=401,
        )

    login(request, user)
    log_event(request, "login_ok", email)

    

    if not remember:
        request.session.set_expiry(0)

    # `login()` cycles the session key, so the inventory row can only be
    # created now.
    track_session(request, user, force=True)

    normalized_email = (user.email or email).strip().lower()
    access = get_user_access(normalized_email)

    authenticated_user = {
        "email": normalized_email,
        "name": (
            user.get_full_name()
            or user.first_name
            or user.email
        ),
        "role": access["role"],
        "authorized_systems": access["authorized_systems"],
    }

    request.session["authenticated_user"] = authenticated_user

    return JsonResponse(
        {
            "authenticated": True,
            "user": authenticated_user,
            # Where the browser should go next. Usually the workspace picker;
            # `/o/authorize/...` when this call was made on behalf of a
            # relying party that is waiting for an authorization code.
            "redirect_to": consume_post_login_redirect(request),
        },
        status=200,
    )


@extend_schema(
    summary="Get current authenticated user",
    description=(
        "Returns information about the currently authenticated user."
    ),
    responses={
        200: OpenApiResponse(
            description="Authenticated user information."
        ),
        401: OpenApiResponse(
            description="The user is not authenticated."
        ),
    },
)
@api_view(["GET"])
def current_user(request):
    if not request.user.is_authenticated:
        return JsonResponse(
            {"authenticated": False},
            status=401,
        )

    authenticated_user = request.session.get("authenticated_user")

    if not authenticated_user:
        return JsonResponse(
            {"authenticated": False},
            status=401,
        )

    # Recalculate access from the current policy rather than trusting
    # old role/system values stored in the session.
    access = get_user_access(authenticated_user.get("email"))

    authenticated_user["role"] = access["role"]
    authenticated_user["authorized_systems"] = access["authorized_systems"]

    # Name comes from `auth.User`, the same row the OIDC claims read, so a
    # name edited in the profile page shows up here, in the tokens, and in
    # every system -- instead of only in the browser that edited it.
    authenticated_user["first_name"] = request.user.first_name
    authenticated_user["last_name"] = request.user.last_name
    authenticated_user["name"] = (
        request.user.get_full_name().strip()
        or authenticated_user.get("name")
        or request.user.email
    )

    picture = _avatar_url(request, request.user)
    if picture:
        authenticated_user["picture"] = picture
    else:
        authenticated_user.pop("picture", None)

    request.session["authenticated_user"] = authenticated_user

    return JsonResponse(
        {
            "authenticated": True,
            "user": authenticated_user,
        }
    )


def _avatar_url(request, user):
    """Absolute URL of this person's avatar, or ``""`` when they have none.

    Returned as a URL rather than inline data so the identity response stays
    small: ``/auth/me/`` is called on every page load of all three systems, and
    a base64 avatar would make each of those responses megabytes wide.

    The URL carries a short-lived signature (see ``avatar_tokens``) because the
    three systems are three different *sites* under the ``onrender.com`` public
    suffix. An ``<img>`` from the PMS or EID origin is a third-party request, so
    it cannot rely on the ``SameSite=None`` session cookie that browsers are
    blocking -- without the token the photo 404s in every system but this one.
    """
    profile = getattr(user, "greenhill_profile", None)
    path = avatar_path(profile, user)

    if not path:
        return ""

    return request.build_absolute_uri(path)


def _profile_for(user):
    """The profile row for this account, created on first use."""
    profile, _created = UserProfile.objects.get_or_create(user=user)
    return profile


def _settings_for(user):
    """The settings row for this account, created with defaults on first use."""
    settings_row, _created = UserSettings.objects.get_or_create(user=user)
    return settings_row


def _settings_payload(settings_row):
    return {
        "in_app_notifications": settings_row.in_app_notifications,
        "email_notifications": settings_row.email_notifications,
        "browser_notifications": settings_row.browser_notifications,
        "appearance": settings_row.appearance,
        "time_zone": settings_row.time_zone,
        "reduce_motion": settings_row.reduce_motion,
    }


def _profile_payload(request, user):
    profile = _profile_for(user)
    return {
        "first_name": user.first_name,
        "last_name": user.last_name,
        # Read-only: the address is the account's identity and the key
        # `AllowedEmail` grants access by, so it is not editable here.
        "work_email": user.email,
        "role": get_user_access(user.email)["role"],
        "avatar_data": profile.avatar_data,
        "picture": _avatar_url(request, user),
    }


@extend_schema(
    summary="Get or update the signed-in person's profile",
    description=(
        "The profile is shared by all three systems: a name saved here is "
        "written to the account itself, so it appears in the OIDC claims and "
        "in every system immediately. The work email is read-only -- it is "
        "the identity the account was granted access under."
    ),
    responses={
        200: OpenApiResponse(description="The profile."),
        401: OpenApiResponse(description="The user is not authenticated."),
        413: OpenApiResponse(description="The avatar is too large."),
    },
)
@api_view(["GET", "POST"])
def user_profile(request):
    if not request.user.is_authenticated:
        return JsonResponse(
            {"authenticated": False},
            status=401,
        )

    user = request.user

    if request.method == "GET":
        return JsonResponse(_profile_payload(request, user))

    data = request.data or {}
    profile = _profile_for(user)

    # Name is written to `auth.User`, not to `UserProfile`, because that is
    # where the OIDC claims read it from. Storing it twice would let the two
    # copies disagree.
    for field, limit in (("first_name", 150), ("last_name", 150)):
        if field in data:
            value = str(data.get(field) or "").strip()
            if len(value) > limit:
                return JsonResponse(
                    {"detail": f"{field} must be {limit} characters or fewer."},
                    status=400,
                )
            setattr(user, field, value)

    user.save(update_fields=["first_name", "last_name"])

    if "avatar_data" in data:
        try:
            profile.set_avatar_data(data.get("avatar_data"))
        except ValueError as error:
            if "too large" in str(error):
                return JsonResponse(
                    {"detail": "The avatar image is too large."},
                    status=413,
                )
            return JsonResponse({"detail": str(error)}, status=400)

        profile.save(update_fields=["avatar_data", "updated_at"])

    # Keep the cached session copy in step so the next page load -- or the
    # next system that asks -- sees the new name without a re-login.
    cached = request.session.get("authenticated_user")
    if cached:
        cached["name"] = (
            user.get_full_name().strip() or cached.get("name") or user.email
        )
        cached["first_name"] = user.first_name
        cached["last_name"] = user.last_name
        request.session["authenticated_user"] = cached

    return JsonResponse(_profile_payload(request, user))


@extend_schema(
    summary="Get or update the signed-in person's preferences",
    description=(
        "Stored per account rather than in the browser, so the same "
        "preferences apply in every system and on every device."
    ),
    responses={
        200: OpenApiResponse(description="The settings."),
        401: OpenApiResponse(description="The user is not authenticated."),
    },
)
@api_view(["GET", "POST"])
def user_settings(request):
    if not request.user.is_authenticated:
        return JsonResponse(
            {"authenticated": False},
            status=401,
        )

    settings_row = _settings_for(request.user)

    if request.method == "GET":
        return JsonResponse(_settings_payload(settings_row))

    data = request.data or {}

    for field in (
        "in_app_notifications",
        "email_notifications",
        "browser_notifications",
        "reduce_motion",
    ):
        if field in data:
            setattr(settings_row, field, bool(data.get(field)))

    if "appearance" in data:
        value = str(data.get("appearance") or "").strip()
        valid = {choice.value for choice in UserSettings.Appearance}
        if value not in valid:
            return JsonResponse(
                {"detail": f"appearance must be one of {sorted(valid)}."},
                status=400,
            )
        settings_row.appearance = value

    if "time_zone" in data:
        value = str(data.get("time_zone") or "").strip()
        if len(value) > 64:
            return JsonResponse(
                {"detail": "time_zone must be 64 characters or fewer."},
                status=400,
            )
        settings_row.time_zone = value

    settings_row.save()

    return JsonResponse(_settings_payload(settings_row))


@extend_schema(
    summary="The signed-in person's avatar image",
    description=(
        "The raw image bytes behind the ``picture`` URL, so the three systems "
        "can render the same photo without each storing a copy."
    ),
    responses={
        200: OpenApiResponse(description="The image bytes."),
        404: OpenApiResponse(description="This account has no avatar."),
    },
)
@api_view(["GET"])
def user_avatar(request):
    if not request.user.is_authenticated:
        # Cross-site embed: the session cookie is frequently withheld here, so
        # the URL's own signature is accepted instead. See avatar_tokens.
        token_user = avatar_user_from_token(request.GET.get("t"))
        if token_user is None:
            return HttpResponse(status=404)
        user = token_user
    else:
        user = request.user

    profile = getattr(user, "greenhill_profile", None)

    if profile is None or not profile.has_avatar:
        return HttpResponse(status=404)

    # "data:image/png;base64,AAAA..." -> ("image/png", "AAAA...")
    header, _, encoded = profile.avatar_data.partition(",")
    content_type = header[len("data:"):].split(";")[0] or "application/octet-stream"

    try:
        image = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        # A stored value we cannot decode is a data problem, not a client
        # error; report it as "no avatar" so the frontend draws initials.
        logger.warning("undecodable avatar for user %s", user.pk)
        return HttpResponse(status=404)

    response = HttpResponse(image, content_type=content_type)

    # Private: the image belongs to one account, so no shared cache may keep
    # a copy. The short lifetime allows a browser to reuse it while a single
    # page is open, which is the only reuse that matters here.
    response["Cache-Control"] = "private, max-age=300"

    return response



@extend_schema(
    summary="Sign out",
    description=(
        "Ends the single sign-on session for this browser and revokes every "
        "OAuth access and refresh token held for the account, so the three "
        "systems lose access immediately rather than when their tokens happen "
        "to expire. Other browsers signed in to the same account are left "
        "alone; use /auth/logout-everywhere/ for that."
    ),
    request=None,
    responses={
        200: OpenApiResponse(
            response=SIGN_OUT_RESPONSE,
            description=(
                "Signed out. The body reports how many sessions, access "
                "tokens and refresh tokens were destroyed."
            ),
        ),
    },
)
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def sign_out(request):
    log_event(request, "logout", getattr(request._request.user, "email", ""))
    result = _end_session(request)
    return JsonResponse(
        {
            "authenticated": False,
            "message": "You have been signed out successfully.",
            **result,
        },
        status=200,
    )
@extend_schema(
    summary="Sign out of every browser",
    description=(
        "Ends every single sign-on session the account holds, on every "
        "device, and revokes all of its OAuth tokens."
    ),
    request=None,
    responses={
        200: OpenApiResponse(
            response=SIGN_OUT_RESPONSE,
            description="Every session was ended.",
        ),
    },
)
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def sign_out_everywhere(request):
    result = _end_session(request, everywhere=True)

    return JsonResponse(
        {
            "authenticated": False,
            "message": "You have been signed out on every device.",
            **result,
        },
        status=200,
    )


@extend_schema(
    summary="Sign out and return to the sign-in page",
    description=(
        "Browser-friendly version of sign out: ends the session, revokes "
        "tokens, then redirects to the frontend. Pass ``next`` to return to "
        "the sign-in page of the system the user signed out from."
    ),
    responses={
        302: OpenApiResponse(description="Redirects to the frontend."),
    },
)
@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def sign_out_redirect(request):
    """Sign out, then send the browser to the auth sign-in page."""
    log_event(request, "logout", getattr(request._request.user, "email", ""))
    """Sign out over a plain link, then land somewhere useful.

    The three systems are separate origins, so none of them can read this
    service's response or share its cookie. A system that wants "Sign out" to
    end the single sign-on session therefore has to navigate the browser here,
    which makes this a top-level GET and means it cannot carry a CSRF token --
    hence no DRF authentication.

    ``next`` is only honoured when it points at a relying party's registered
    frontend and is one of the origins this service has been told to trust.
    Logout links are trivially forgeable, so an unchecked ``next`` here would
    be an open redirect on the sign-out path -- exactly where a phisher wants
    one, because the user is already primed to believe they are being returned
    to a familiar login screen.
    """
    target = _post_logout_target(request)
    _end_session(request)

    return redirect(target or f"{get_frontend_url()}/")


def _post_logout_target(request):
    """Return an absolute ``next`` URL to send the browser to, or ``""``.

    Only an absolute URL on a trusted, registered origin qualifies; anything
    else is dropped and the caller falls back to the frontend root. A relative
    path is refused on purpose: it would resolve against *this* service, which
    serves no frontend routes, so the user would get a 404 immediately after
    signing out.
    """
    target = (request.GET.get("next") or "").strip()
    if not target:
        return ""

    if "://" not in target:
        logger.warning("refused relative post-logout redirect %r", target[:200])
        return ""

    if not url_has_allowed_host_and_scheme(
        target,
        allowed_hosts=_trusted_post_logout_hosts(),
        require_https=request.is_secure(),
    ):
        logger.warning("refused post-logout redirect to %r", target[:200])
        return ""

    return target


def _trusted_post_logout_hosts():
    """Hosts a sign-out may bounce the browser to.

    Two sources, both authoritative for "somewhere we are willing to send a
    person": this service's own configured frontend and CORS origins, plus the
    ``post_logout_redirect_uris`` each relying party registered. The second is
    the same data ``/o/logout/`` already trusts for exactly this purpose, so a
    new system only has to be seeded -- it does not need a deploy here.
    """
    hosts = {get_frontend_url().split("://", 1)[-1].rstrip("/")}

    for origin in settings.CORS_ALLOWED_ORIGINS:
        hosts.add(origin.split("://", 1)[-1].rstrip("/"))

    for application in get_application_model().objects.all():
        for uri in (application.post_logout_redirect_uris or "").split():
            if "://" in uri:
                hosts.add(uri.split("://", 1)[-1].rstrip("/").split("/")[0])

    return hosts

# ---------------------------------------------------------------------------
# Session manager
#
# These endpoints are what the frontend's "active sessions" screen uses. They
# are deliberately CSRF protected (DRF's SessionAuthentication enforces it),
# unlike sign_out, because guessing a session id here would let an attacker
# terminate somebody else's session.
# ---------------------------------------------------------------------------


@extend_schema(
    summary="List active sessions",
    description=(
        "Returns every browser currently signed in to the account, newest "
        "activity first, with the current session flagged."
    ),
    responses={200: SESSION_LIST_RESPONSE},
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def session_list(request):
    sessions = active_sessions(request.user)
    current_key = getattr(request.session, "session_key", None)

    return JsonResponse(
        {
            "count": sessions.count(),
            "sessions": [
                serialize_session(session, current_key)
                for session in sessions
            ],
        },
        status=200,
    )


@extend_schema(
    summary="Revoke one session",
    description=(
        "Signs one browser out. The session cookie in that browser stops "
        "working immediately."
    ),
    request=None,
    responses={200: SESSION_REVOKE_RESPONSE},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def session_revoke(request, session_id):
    session = get_object_or_404(
        UserSession,
        pk=session_id,
        user=request.user,
        revoked_at__isnull=True,
    )

    revoke_session(session)

    return JsonResponse(
        {
            "revoked": True,
            "session_id": session_id,
        },
        status=200,
    )


@extend_schema(
    summary="Revoke all other sessions",
    description="Signs every other browser out, keeping the current one.",
    request=None,
    responses={200: SESSION_REVOKE_OTHERS_RESPONSE},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def session_revoke_others(request):
    current_key = getattr(request.session, "session_key", None)
    revoked = revoke_other_sessions(request.user, keep_session_key=current_key)

    return JsonResponse(
        {
            "revoked": True,
            "sessions_revoked": revoked,
        },
        status=200,
    )


@extend_schema(
    summary="Revoke every session",
    description="Signs the account out everywhere, including this browser.",
    request=None,
    responses={200: SESSION_REVOKE_ALL_RESPONSE},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def session_revoke_all(request):
    current_key = getattr(request.session, "session_key", None)
    revoked = revoke_all_sessions(request.user)
    revoke_user_tokens(request.user)

    logout(request)

    return JsonResponse(
        {
            "authenticated": False,
            "revoked": True,
            "sessions_revoked": revoked,
            "current_session_key_present": bool(current_key),
        },
        status=200,
    )


@extend_schema(
    summary="Fetch a CSRF token",
    description=(
        "Sets the csrftoken cookie the frontend must echo in the "
        "X-CSRFToken header when calling the session manager endpoints."
    ),
    responses={
        200: OpenApiResponse(description="CSRF cookie set."),
    },
)
@ensure_csrf_cookie
@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def csrf_token(request):
    return JsonResponse({"detail": "CSRF cookie set."}, status=200)           
    # The token is returned in the body as well as set as a cookie. The three
    # systems call this backend from a different origin, where JavaScript
    # cannot read the cookie at all, so being told the value here is the only
    # way they can echo it in the ``X-CSRFToken`` header. It is not a secret
    # leak: django-cors-headers only lets the origins listed in
    # ``CORS_ALLOWED_ORIGINS`` read this response, and any other page gets the
    # normal CORS refusal instead of the body.
    return JsonResponse(
        {
            "detail": "CSRF cookie set.",
            "csrfToken": get_token(request),
        },
        status=200,
    )           
