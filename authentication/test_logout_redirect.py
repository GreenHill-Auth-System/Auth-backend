"""Sign-out has to work from any of the three systems.

A relying party is a separate origin, so it cannot read this service's
response or share its cookie. Its "Sign out" therefore navigates the browser
here, and everything that matters has to happen on this one request:

* the identity provider session ends,
* every system's OAuth tokens are revoked, not just the one that asked, and
* the browser is sent somewhere sensible -- the person's sign-in page.

These tests pin all three down, plus the rule that ``next`` cannot be used as
an open redirect on the sign-out path.
"""

from datetime import timedelta

from django.contrib.auth import (
    BACKEND_SESSION_KEY,
    SESSION_KEY,
    get_user_model,
)
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.test import RequestFactory, TestCase
from django.urls import resolve
from django.utils import timezone
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
)

from .models import UserSession
from .oauth_logout import GreenHillRPInitiatedLogoutView
from .views import get_frontend_url

User = get_user_model()
Application = get_application_model()
AccessToken = get_access_token_model()

# The origins the three systems are served from. They are listed in
# ``settings.CORS_ALLOWED_ORIGINS``, which is one of the two things
# ``_trusted_post_logout_hosts`` reads.
SYSTEM_ORIGINS = [
    "https://greenhill-eid-frontend.onrender.com/",
    "https://pms-frontend-4fm8.onrender.com/",
    "https://165.232.50.141.sslip.io/",
]


def make_user(email="signout@greenhillacademy.ac.ug"):
    return User.objects.create_user(
        username=email, email=email, password="pw-for-tests-123"
    )


def make_application(name="GreenHill EID"):
    return Application.objects.create(
        name=name,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://eid.example/callback",
        skip_authorization=True,
    )


class LogoutRedirectTests(TestCase):
    def setUp(self):
        self.user = make_user()

    def _sign_in(self):
        self.client.force_login(self.user)
        return self.client.session.session_key

    def test_logs_out_and_redirects_to_the_frontend(self):
        self._sign_in()

        response = self.client.get("/auth/logout-redirect/")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], f"{get_frontend_url()}/")
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_destroys_the_session_the_browser_holds(self):
        session_key = self._sign_in()
        session = Session.objects.get(session_key=session_key)

        self.client.get("/auth/logout-redirect/")

        self.assertFalse(
            Session.objects.filter(pk=session.pk).exists(),
            "the row behind the browser's cookie must be gone, not just unset",
        )

    def test_retires_the_session_inventory_row(self):
        session_key = self._sign_in()
        inventory = UserSession.objects.create(
            user=self.user, session_key=session_key
        )

        self.client.get("/auth/logout-redirect/")

        inventory.refresh_from_db()
        self.assertIsNotNone(
            inventory.revoked_at,
            "the session manager must not keep listing a session that ended",
        )

    def test_revokes_tokens_belonging_to_every_system(self):
        self._sign_in()

        for name in ("GreenHill EID", "GreenHill PMS", "GreenHill ISMP"):
            application = make_application(name)
            AccessToken.objects.create(
                user=self.user,
                application=application,
                token=f"token-for-{name}",
                expires=timezone.now() + timedelta(hours=1),
            )

        self.client.get("/auth/logout-redirect/")

        self.assertEqual(
            AccessToken.objects.filter(user=self.user).count(),
            0,
            "signing out of one system must stop the other two as well",
        )

    def test_returns_a_person_to_the_system_they_signed_out_from(self):
        for origin in SYSTEM_ORIGINS:
            with self.subTest(origin=origin):
                self._sign_in()

                response = self.client.get(
                    "/auth/logout-redirect/", {"next": origin}
                )

                self.assertEqual(response.status_code, 302)
                self.assertEqual(response["Location"], origin)

    def test_refuses_a_next_pointing_at_an_untrusted_host(self):
        self._sign_in()

        response = self.client.get(
            "/auth/logout-redirect/", {"next": "https://evil.example.com/"}
        )

        self.assertEqual(response["Location"], f"{get_frontend_url()}/")

    def test_refuses_a_relative_next(self):
        # A relative path would resolve against this service, which serves no
        # frontend routes -- the person would meet a 404 straight after signing
        # out.
        self._sign_in()

        response = self.client.get("/auth/logout-redirect/", {"next": "/somewhere"})

        self.assertEqual(response["Location"], f"{get_frontend_url()}/")

    def test_still_redirects_when_nobody_is_signed_in(self):
        response = self.client.get("/auth/logout-redirect/")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], f"{get_frontend_url()}/")

    def test_the_signing_out_browser_is_the_only_one_ended(self):
        self._sign_in()

        other = make_user("second-device@greenhillacademy.ac.ug")
        other_session = SessionStore()
        other_session[SESSION_KEY] = str(other.pk)
        other_session[BACKEND_SESSION_KEY] = (
            "django.contrib.auth.backends.ModelBackend"
        )
        other_session.save()

        self.client.get("/auth/logout-redirect/")

        self.assertTrue(
            Session.objects.filter(session_key=other_session.session_key).exists(),
            "signing out here must not end a different account's session",
        )


class RPInitiatedLogoutTests(TestCase):
    """The standard ``/o/logout/`` endpoint, which relying parties may use."""

    def setUp(self):
        self.user = make_user()

    def _request(self):
        request = RequestFactory().get("/o/logout/")
        request.session = SessionStore()
        request.session[SESSION_KEY] = str(self.user.pk)
        request.session[BACKEND_SESSION_KEY] = (
            "django.contrib.auth.backends.ModelBackend"
        )
        request.session.save()
        request.user = self.user
        return request

    def test_the_project_view_answers_o_logout(self):
        match = resolve("/o/logout/")

        self.assertIs(
            match.func.view_class,
            GreenHillRPInitiatedLogoutView,
            "the override must be matched before the oauth2_provider include",
        )

    def test_ends_the_session_and_retires_its_inventory_row(self):
        request = self._request()
        session_key = request.session.session_key
        inventory = UserSession.objects.create(
            user=self.user, session_key=session_key
        )

        view = GreenHillRPInitiatedLogoutView()
        view.request = request
        view.do_logout()

        inventory.refresh_from_db()
        self.assertIsNotNone(inventory.revoked_at)
        self.assertFalse(Session.objects.filter(session_key=session_key).exists())

    def test_still_lets_the_toolkit_revoke_the_tokens(self):
        application = make_application()
        AccessToken.objects.create(
            user=self.user,
            application=application,
            token="rp-logout-token",
            expires=timezone.now() + timedelta(hours=1),
        )

        view = GreenHillRPInitiatedLogoutView()
        view.request = self._request()
        view.do_logout(token_user=self.user)

        self.assertEqual(AccessToken.objects.filter(user=self.user).count(), 0)
