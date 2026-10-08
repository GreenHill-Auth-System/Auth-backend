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
    OpenApiExample,
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
        "Starts the Google Workspace OAuth 2.0 / OpenID Connect "
        "authentication flow and redirects the user to Google."
    ),
    responses={
        302: OpenApiResponse(
            description="Redirects the user to Google for authentication."
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
        "Handles the callback from Google after successful "
        "OAuth 2.0 / OpenID Connect authentication."
    ),
    responses={
        302: OpenApiResponse(
            description=(
                "Redirects the authenticated Greenhill user "
                "to the frontend workspace selector."
            )
        ),
        400: OpenApiResponse(
            description=(
                "OAuth state, verifier, token exchange, "
                "or ID token error."
            )
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
    except Exception as exc:
        return HttpResponse(
            f"Google token exchange failed: {exc}",
            status=400,
        )

    credentials = flow.credentials

    try:
        google_user = id_token.verify_oauth2_token(
            credentials.id_token,
            requests.Request(),
            os.getenv("GOOGLE_CLIENT_ID"),
        )
    except Exception as exc:
        return HttpResponse(
            f"Google ID token verification failed: {exc}",
            status=400,
        )

    email = google_user.get("email")
    name = google_user.get("name")

    if not is_greenhill_email(email):
        frontend_url = os.getenv(
            "FRONTEND_URL",
            "http://localhost:5173",
        ).rstrip("/")

        return redirect(
            f"{frontend_url}/?error=greenhill_account_required"
        )

    authentication_result = {
        "email": email,
        "role": "Greenhill User",
        "authorized_systems": [
            "EID",
            "Procurement",
            "Incident Service Management",
        ],
    }

    User = get_user_model()

    user, created = User.objects.get_or_create(
        email=email,
        defaults={
            "username": email,
            "first_name": name or "",
        },
    )

    login(request, user)

    request.session["authenticated_user"] = {
        "email": authentication_result["email"],
        "name": name,
        "role": authentication_result["role"],
        "authorized_systems": authentication_result[
            "authorized_systems"
        ],
    }

    frontend_url = os.getenv(
        "FRONTEND_URL",
        "http://localhost:5173",
    ).rstrip("/")

    return redirect(
        f"{frontend_url}/workspaces?login=success"
    )


@extend_schema(
    summary="Manual login",
    description=(
        "Authenticates a Greenhill user using their email "
        "and application password."
    ),
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string",
                    "format": "email",
                    "example": "user@greenhillacademy.ac.ug",
                },
                "password": {
                    "type": "string",
                    "format": "password",
                    "example": "your-password",
                },
                "remember": {
                    "type": "boolean",
                    "example": True,
                },
            },
            "required": [
                "email",
                "password",
            ],
        }
    },
    examples=[
        OpenApiExample(
            "Manual login example",
            value={
                "email": "user@greenhillacademy.ac.ug",
                "password": "your-password",
                "remember": True,
            },
            request_only=True,
        ),
    ],
    responses={
        200: OpenApiResponse(
            description="Authentication successful."
        ),
        400: OpenApiResponse(
            description="Invalid or incomplete login request."
        ),
        401: OpenApiResponse(
            description="Invalid email or password."
        ),
        403: OpenApiResponse(
            description=(
                "The email address is not a Greenhill "
                "Academy work email."
            )
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
    remember = bool(data.get("remember", False))

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

    if user is None:
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

    if not user.is_active:
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

    authenticated_user = {
        "email": user.email or email,
        "name": (
            user.get_full_name()
            or user.first_name
            or user.email
        ),
        "role": "Greenhill User",
        "authorized_systems": [
            "EID",
            "Procurement",
            "Incident Service Management",
        ],
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
        "Returns information about the currently authenticated "
        "Greenhill user."
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
            {
                "authenticated": False,
            },
            status=401,
        )

    authenticated_user = request.session.get(
        "authenticated_user"
    )

    if not authenticated_user:
        return JsonResponse(
            {
                "authenticated": False,
            },
            status=401,
        )

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
    User = get_user_model()

    email = "refactory@greenhillacademy.ac.ug"

    user = User.objects.filter(email=email).first()

    if not user:
        return JsonResponse(
            {
                "exists": False,
            },
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