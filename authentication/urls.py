"""Authentication and single sign-on endpoints.

Two kinds of route live here:

* **Sign-in** -- start a Google sign-in, handle its callback, or authenticate
  with an email and password.
* **Session management** -- who am I, which browsers am I signed in on, and how
  do I sign out of one, all, or everywhere.

The OAuth 2.0 / OIDC endpoints the three systems talk to (``/o/authorize/``,
``/o/token/``, ``/o/userinfo/``, ``/o/jwks/``, ...) are mounted under ``/o/``
by the toolkit itself, not here.
"""

from django.urls import path

from . import views


urlpatterns = [
    # ---- Sign-in -------------------------------------------------------
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

    # ---- Current identity ----------------------------------------------
    path(
        "me/",
        views.current_user,
        name="current_user",
    ),

    # ---- Profile and preferences ---------------------------------------
    #
    # Stored per account, not per browser. `localStorage` is scoped to one
    # origin, so anything kept there is invisible to the other two systems and
    # to a private window -- which is the difference between "one account" and
    # "one account that looks different in three places".
    path(
        "profile/",
        views.user_profile,
        name="user_profile",
    ),
    path(
        "settings/",
        views.user_settings,
        name="user_settings",
    ),
    path(
        "avatar/",
        views.user_avatar,
        name="user_avatar",
    ),

    # ---- Sign-out ------------------------------------------------------
    path(
        "logout/",
        views.sign_out,
        name="sign_out",
    ),
    path(
        "logout-everywhere/",
        views.sign_out_everywhere,
        name="sign_out_everywhere",
    ),
    path(
        "logout-redirect/",
        views.sign_out_redirect,
        name="sign_out_redirect",
    ),

    # ---- Session manager -----------------------------------------------
    path(
        "sessions/",
        views.session_list,
        name="session_list",
    ),
    path(
        "sessions/revoke-others/",
        views.session_revoke_others,
        name="session_revoke_others",
    ),
    path(
        "sessions/revoke-all/",
        views.session_revoke_all,
        name="session_revoke_all",
    ),
    path(
        "sessions/<int:session_id>/revoke/",
        views.session_revoke,
        name="session_revoke",
    ),

    # ---- Frontend bootstrap --------------------------------------------
    path(
        "csrf/",
        views.csrf_token,
        name="csrf_token",
    ),
]