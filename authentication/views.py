
import base64
import hashlib
import os
import secrets

from django.contrib.auth import (
    authenticate,
    get_user_model,
    login,
    logout,
) 
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect

from drf_spectacular.utils import (
    OpenApiResponse,
    extend_schema,
)
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import AllowAny

from google.auth.transport import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow

from authentication.domain_guard import is_greenhill_email
from authentication.models import AllowedEmail

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

# Initial GreenHill access policy.
CEO_EMAIL = "refactory@greenhillacademy.ac.ug"
CEO_ROLE = "CEO"

INITIAL_AUTHORIZED_SYSTEMS = [
    "EID",
    "Procurement",
    "Incident Service Management",
]


def get_user_access(email):
    """
    Return the role and systems assigned to a user.

    The AllowedEmail table is checked first. The hardcoded CEO is a
    temporary fallback until the CEO has a row in the table.
    """
    normalized_email = (email or "").strip().lower()

    entry = AllowedEmail.objects.filter(
        email=normalized_email,
        is_active=True,
    ).first()

    if entry:
        return {
            "role": entry.role,
            "authorized_systems": list(entry.authorized_systems),
        }

    if normalized_email == CEO_EMAIL:
        return {
            "role": CEO_ROLE,
            "authorized_systems": INITIAL_AUTHORIZED_SYSTEMS.copy(),
        }

    return {
        "role": "Greenhill User",
        "authorized_systems": [],
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


def get_frontend_url():
    return os.getenv(
        "FRONTEND_URL",
        "http://localhost:5173",
    ).rstrip("/")


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

    access = get_user_access(email)

    User = get_user_model()

    user, created = User.objects.get_or_create(
        email=email,
        defaults={
            "username": email,
            "first_name": name,
        },
    )

    if not user.is_active:
        return redirect(
            f"{get_frontend_url()}/?error=account_inactive"
        )

    login(request, user)

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

    return redirect(
        f"{get_frontend_url()}/workspaces?login=success"
    )


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

    user = authenticate(
        request,
        username=email,
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
    description="Signs out the currently authenticated user.",
    responses={
        200: OpenApiResponse(
            description="User successfully signed out."
        ),
    },
)
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def sign_out(request):
    logout(request)

    return JsonResponse(
        {
            "authenticated": False,
            "message": "You have been signed out successfully.",
        },
        status=200,
    )


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def diagnostic_test_user(request):
    email = CEO_EMAIL
    User = get_user_model()
    user = User.objects.filter(email__iexact=email).first()

    if not user:
        return JsonResponse(
            {"exists": False},
            status=200,
        )

    return JsonResponse(
        {
            "exists": True,
            "email": user.email,
            "username": user.username,
            "active": user.is_active,
        },
        status=200,
    )
@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def sign_out_redirect(request):
    """Sign out, then send the browser to the auth sign-in page."""
    logout(request)
    return redirect(f"{get_frontend_url()}/")