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
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from google.auth.transport import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow

from authentication.domain_guard import is_greenhill_email


# Google OAuth scopes required to authenticate the user's
# Google Workspace identity and retrieve basic profile information.
GOOGLE_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]


# Manual login error messages returned by the backend.
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
    # Generate a cryptographically secure PKCE code verifier.
    #
    # The verifier is stored in the user's session and later supplied
    # when exchanging the authorization code for Google tokens.
    return secrets.token_urlsafe(64)


def generate_code_challenge(code_verifier):
    # Generate the S256 PKCE code challenge from the verifier.
    digest = hashlib.sha256(
        code_verifier.encode("ascii")
    ).digest()

    return base64.urlsafe_b64encode(
        digest
    ).rstrip(b"=").decode("ascii")


def google_login(request):
    # Start the Google OAuth 2.0 / OpenID Connect authentication flow.
    #
    # The backend:
    # 1. Creates the Google OAuth client configuration.
    # 2. Generates a PKCE verifier and challenge.
    # 3. Generates an OAuth state value for CSRF protection.
    # 4. Stores the state and verifier in the user's session.
    # 5. Redirects the user to Google for authentication.

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                "client_secret": os.getenv(
                    "GOOGLE_CLIENT_SECRET"
                ),
                "auth_uri": (
                    "https://accounts.google.com/o/oauth2/auth"
                ),
                "token_uri": (
                    "https://oauth2.googleapis.com/token"
                ),
            }
        },
        scopes=GOOGLE_SCOPES,
    )

    flow.redirect_uri = os.getenv(
        "GOOGLE_REDIRECT_URI"
    )

    # Generate PKCE values to protect the authorization-code exchange.
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(
        code_verifier
    )

    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="select_account",
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )

    # Store security values in the user's session so they can be
    # validated when Google redirects back to the callback endpoint.
    request.session["google_oauth_state"] = state
    request.session["google_code_verifier"] = code_verifier

    return redirect(authorization_url)


@csrf_exempt
@require_POST
def manual_login(request):
    # Authenticate a user through the application's local
    # Django authentication system.
    #
    # This endpoint does not receive or verify Google Workspace
    # passwords. Google Workspace authentication remains handled
    # through the Google OAuth/OIDC flow above.

    # Read the submitted credentials from the JSON request body.
    import json

    try:
        data = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return JsonResponse(
            {
                "authenticated": False,
                "error": "invalid_request",
                "message": "Invalid login request.",
            },
            status=400,
        )

    email = str(data.get("email") or "").strip().lower()
    password = str(data.get("password") or "")
    remember = bool(data.get("remember", False))

    # Both credentials are required before authentication can begin.
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

    # Only Greenhill Workspace email addresses may use
    # the manual application login.
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

    # Authenticate against Django's configured authentication backend.
    #
    # The current project creates Django usernames from the user's
    # Greenhill email address, so the email is supplied as username.
    user = authenticate(
        request,
        username=email,
        password=password,
    )

    # Use one generic error for invalid credentials so that the
    # endpoint does not reveal whether an account exists.
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

    # Do not allow disabled Django accounts to authenticate.
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

    # Create the authenticated Django session.
    login(request, user)

    # Keep the session alive only for the browser session when
    # the user did not select "Remember me".
    if not remember:
        request.session.set_expiry(0)

    # Return the same basic workspace structure used by
    # the Google authentication flow.
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


def google_callback(request):
    # Handle Google's OAuth callback.
    #
    # The backend:
    # 1. Validates the OAuth state.
    # 2. Retrieves the PKCE verifier.
    # 3. Exchanges the authorization code for Google credentials.
    # 4. Verifies the Google ID token.
    # 5. Extracts the user's identity.
    # 6. Checks that the email belongs to GreenHill Workspace.
    # 7. Creates the local Django session.
    # 8. Redirects the authenticated user to the React workspace page.
    #
    # Temporary development authorization:
    # Any verified Google account belonging to the official
    # GreenHill Workspace domain can access the workspace page.
    #
    # System-level authorization for EID, Procurement, and
    # Incident Service Management will be added separately.

    # Retrieve the security values created during the login request.
    state = request.session.get(
        "google_oauth_state"
    )
    code_verifier = request.session.get(
        "google_code_verifier"
    )

    # OAuth state protects the callback against CSRF attacks.
    if not state:
        return HttpResponse(
            "OAuth state is missing from the session.",
            status=400,
        )

    # PKCE verifier is required to securely exchange
    # the authorization code.
    if not code_verifier:
        return HttpResponse(
            "OAuth code verifier is missing from the session.",
            status=400,
        )

    # Ensure the state returned by Google matches the state
    # originally generated by our backend.
    if request.GET.get("state") != state:
        return HttpResponse(
            "Invalid OAuth state.",
            status=400,
        )

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                "client_secret": os.getenv(
                    "GOOGLE_CLIENT_SECRET"
                ),
                "auth_uri": (
                    "https://accounts.google.com/o/oauth2/auth"
                ),
                "token_uri": (
                    "https://oauth2.googleapis.com/token"
                ),
            }
        },
        scopes=GOOGLE_SCOPES,
        state=state,
    )

    flow.redirect_uri = os.getenv(
        "GOOGLE_REDIRECT_URI"
    )

    # Exchange Google's authorization code for OAuth credentials.
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

    # Verify the Google ID token before trusting any identity
    # information contained within it.
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

    # Extract the authenticated user's basic Google identity.
    email = google_user.get("email")
    name = google_user.get("name")

    # Only Google Workspace accounts belonging to the official
    # GreenHill domain are allowed to continue.
    #
    # Non-GreenHill accounts are redirected back to the frontend
    # with a simple error code so that the login page can display
    # a user-friendly message.
    if not is_greenhill_email(email):
        frontend_url = os.getenv(
            "FRONTEND_URL",
            "http://localhost:5173",
        ).rstrip("/")

        return redirect(
            f"{frontend_url}/?error=greenhill_account_required"
        )

    # Temporary development authorization:
    # A verified GreenHill Workspace account is allowed to enter
    # the workspace page. Detailed system authorization will be
    # performed when the user selects a specific workspace.
    authentication_result = {
        "email": email,
        "role": "Greenhill User",
        "authorized_systems": [
            "EID",
            "Procurement",
            "Incident Service Management",
        ],
    }

    # Get the project's configured Django user model.
    User = get_user_model()

    # Create a local application user for a first-time GreenHill user,
    # or retrieve the existing account for a returning user.
    user, created = User.objects.get_or_create(
        email=email,
        defaults={
            "username": email,
            "first_name": name or "",
        },
    )

    # Authenticate the verified Google identity into the local
    # Django application session.
    login(request, user)

    # Store the authenticated user's workspace information
    # in the server-side Django session.
    request.session["authenticated_user"] = {
        "email": authentication_result["email"],
        "name": name,
        "role": authentication_result["role"],
        "authorized_systems": authentication_result[
            "authorized_systems"
        ],
    }

    # Redirect the authenticated user to the React workspace page
    # with a success indicator for the frontend.
    frontend_url = os.getenv(
        "FRONTEND_URL",
        "http://localhost:5173",
    ).rstrip("/")

    return redirect(
        f"{frontend_url}/workspaces?login=success"
    )


def current_user(request):
    # Return the authenticated user's workspace information
    # stored in the Django session after successful login.

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


@csrf_exempt
@require_POST
def sign_out(request):
    # Destroy the authenticated Django session.
    logout(request)

    # Confirm that the user is no longer authenticated.
    return JsonResponse(
        {
            "authenticated": False,
            "message": "You have been signed out successfully.",
        },
        status=200,
    )