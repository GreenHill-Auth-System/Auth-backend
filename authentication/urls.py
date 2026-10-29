from django.conf import settings
from django.urls import path

from . import views


urlpatterns = [
    path(
        "google/login/",
        views.google_login,
        name="google_login",
    ),
    path(
        "google/callback/",
        views.google_callback,
        name="google_callback",
    ),
    path(
        "login/",
        views.manual_login,
        name="manual_login",
    ),
    path(
        "me/",
        views.current_user,
        name="current_user",
    ),
    path(
        "logout/",
        views.sign_out,
        name="sign_out",
    ),
    path(
        "logout-redirect/",
        views.sign_out_redirect,
        name="sign_out_redirect",
    ),
]

# Diagnostic endpoint exists only in local development (DEBUG=true).
if settings.DEBUG:
    urlpatterns += [
        path(
            "diagnostic/test-user/",
            views.diagnostic_test_user,
            name="diagnostic_test_user",
        ),
    ]