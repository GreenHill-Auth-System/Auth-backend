
import base64
import hashlib
import os
import secrets
from rest_framework.decorators import throttle_classes
from .throttles import LoginRateThrottle

from django.contrib.auth import (
    authenticate,
    get_user_model,
    login,
    logout,
)
from django.core.exceptions import DisallowedHost
from django.http import HttpResponse, JsonResponse
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

from authentication.access import get_user_access
from authentication.domain_guard import (
    GREENHILL_EMAIL_HINT,
    is_greenhill_email,
    is_valid_greenhill_email,
)
from authentication.models import UserSession
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

    return redirect(authorization_url)


@extend_schema(
    summary="Google OAuth callback",
    description=(
        "Verifies the Google identity, checks the GreenHill email domain, "
        "creates or retrieves the local user, and establishes a session."
    ),
    responses={
        302: OpenApiResponse(
            description="Redirects to the frontend workspace selector."
        ),
        400: OpenApiResponse(
            description="OAuth state, verifier, token exchange, or ID token error."
        ),
    },
)
@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def google_callback(request):
    state = request.session.get("google_oauth_state")
    code_verifier = request.session.get("google_code_verifier")

    if not state:
        return HttpResponse(
            "OAuth state is missing from the session.",
            status=400,
        )

    if not code_verifier:
        return HttpResponse(
            "OAuth code verifier is missing from the session.",
            status=400,
        )

    if request.GET.get("state") != state:
        return HttpResponse(
            "Invalid OAuth state.",
            status=400,
        )

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
    except Exception:
        return HttpResponse(
            "Google token exchange failed.",
            status=400,
        )

    credentials = flow.credentials

    try:
        google_user = id_token.verify_oauth2_token(
            credentials.id_token,
            requests.Request(),
            os.getenv("GOOGLE_CLIENT_ID"),
        )
    except Exception:
        return HttpResponse(
            "Google ID token verification failed.",
            status=400,
        )

    email = (google_user.get("email") or "").strip().lower()
    name = google_user.get("name") or ""

    if not is_greenhill_email(email):
        return redirect(
            f"{get_frontend_url()}/?error=greenhill_account_required"
        )

    # Google must assert that it has verified this address, and a Workspace
    # account must belong to GreenHill's hosted domain. Checking only the email
    # suffix would trust an unverified address asserted by a Workspace admin.
    claims_ok, claim_error = google_claims_are_trustworthy(google_user)
    if not claims_ok:
        return redirect(
            f"{get_frontend_url()}/?error={claim_error}"
        )

    access = get_user_access(email)

    # Resolve the identity before creating anything: a Google subject that is
    # already bound to somebody else must never leave a stray account behind.
    try:
        user, _created = resolve_google_user(google_user)
    except ValueError:
        return redirect(
            f"{get_frontend_url()}/?error=identity_conflict"
        )

    if not user.is_active:
        return redirect(
            f"{get_frontend_url()}/?error=account_inactive"
        )

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
    return redirect(consume_post_login_redirect(request))


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
    request.session["authenticated_user"] = authenticated_user

    return JsonResponse(
        {
            "authenticated": True,
            "user": authenticated_user,
        }
    )


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
        "tokens, then redirects to the frontend."
    ),
    responses={
        302: OpenApiResponse(description="Redirects to the frontend."),
    },
)
@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def sign_out_redirect(request):
    _end_session(request)
    return redirect(f"{get_frontend_url()}/")


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