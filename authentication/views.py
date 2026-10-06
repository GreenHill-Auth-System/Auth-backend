import os

from django.http import HttpResponse
from django.shortcuts import redirect
from google_auth_oauthlib.flow import Flow


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
        scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
        ],
    )

    flow.redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")

    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="select_account",
    )

    request.session["google_oauth_state"] = state

    return redirect(authorization_url)


def google_callback(request):
    return HttpResponse("Google callback reached successfully.")