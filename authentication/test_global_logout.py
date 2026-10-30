"""Tests for global sign-out and token revocation.

Signing out has to mean the three systems lose access immediately. That is two
separate jobs: destroy the IdP session (no new tokens) and delete the OAuth
tokens (no continued use of existing ones).
"""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.test import TestCase
from django.utils import timezone
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_refresh_token_model,
)

from .models import UserSession
from .tokens import revoke_application_tokens, revoke_user_tokens

User = get_user_model()
Application = get_application_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()


def make_user(email="cnmusisi@greenhillacademy.ac.ug"):
    return User.objects.create_user(username=email, email=email, password="pw-for-tests-123")


def make_application(name="GreenHill EID"):
    return Application.objects.create(
        name=name,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://eid.example/callback",
        skip_authorization=True,
    )


def store_session(session_key):
    """Persist a Django session row so it can be found and destroyed.

    Uses `get_or_create` because several tests in a class reuse the same key and
    `session_key` is the primary key of `django_session`.
    """
    session, _ = Session.objects.get_or_create(
        session_key=session_key,
        defaults={
            "session_data": "",
            "expire_date": timezone.now() + timedelta(days=1),
        },
    )
    return session


class RevokeUserTokensTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.application = make_application()

    def _grant(self, client=None):
        refresh = RefreshToken.objects.create(
            user=self.user,
            application=client or self.application,
            token="refresh-" + str(RefreshToken.objects.count() + 1),
        )
        AccessToken.objects.create(
            user=self.user,
            application=client or self.application,
            token="access-" + str(AccessToken.objects.count() + 1),
            expires=timezone.now() + timedelta(hours=1),
            source_refresh_token=refresh,
        )
        return refresh

    def test_deletes_access_and_refresh_tokens(self):
        self._grant()
        result = revoke_user_tokens(self.user)

        self.assertEqual(result["access_tokens"], 1)
        self.assertEqual(result["refresh_tokens"], 1)
        self.assertEqual(AccessToken.objects.filter(user=self.user).count(), 0)
        self.assertEqual(RefreshToken.objects.filter(user=self.user).count(), 0)

    def test_is_idempotent(self):
        self._grant()
        revoke_user_tokens(self.user)
        self.assertEqual(
            revoke_user_tokens(self.user),
            {"access_tokens": 0, "refresh_tokens": 0},
        )

    def test_none_user_is_a_no_op(self):
        self.assertEqual(
            revoke_user_tokens(None),
            {"access_tokens": 0, "refresh_tokens": 0},
        )

    def test_leaves_other_accounts_alone(self):
        other = make_user("other@greenhillacademy.ac.ug")
        self._grant()
        AccessToken.objects.create(
            user=other,
            application=self.application,
            token="other-access",
            expires=timezone.now() + timedelta(hours=1),
        )

        revoke_user_tokens(self.user)

        self.assertEqual(AccessToken.objects.filter(user=other).count(), 1)

    def test_can_scope_to_one_application(self):
        second = make_application("GreenHill Procurement (PMS)")
        self._grant()
        self._grant(client=second)

        result = revoke_application_tokens(self.user, self.application)

        self.assertEqual(result["access_tokens"], 1)
        self.assertEqual(
            AccessToken.objects.filter(user=self.user).count(),
            1,
        )
        self.assertEqual(
            AccessToken.objects.filter(application=second).count(),
            1,
        )


class GlobalLogoutApiTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.application = make_application()
        self.client.force_login(self.user)
        self.session_key = self.client.session.session_key
        UserSession.objects.create(user=self.user, session_key=self.session_key)
        store_session(self.session_key)

    def test_sign_out_destroys_the_session(self):
        response = self.client.post("/auth/logout/")

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["authenticated"])
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertFalse(Session.objects.filter(session_key=self.session_key).exists())

    def test_sign_out_revokes_tokens(self):
        AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token="access-token-1",
            expires=timezone.now() + timedelta(hours=1),
        )

        response = self.client.post("/auth/logout/")

        self.assertEqual(response.json()["access_tokens_revoked"], 1)
        self.assertEqual(AccessToken.objects.filter(user=self.user).count(), 0)

    def test_sign_out_without_a_session_still_succeeds(self):
        self.client.logout()
        response = self.client.post("/auth/logout/")
        self.assertEqual(response.status_code, 200)

    def test_logout_everywhere_kills_other_browsers_too(self):
        other = UserSession.objects.create(user=self.user, session_key="other-key")
        store_session("other-key")

        response = self.client.post("/auth/logout-everywhere/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["sessions_revoked"], 2)
        self.assertFalse(Session.objects.filter(session_key=other.session_key).exists())
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_logout_redirect_sends_the_browser_away(self):
        response = self.client.get("/auth/logout-redirect/")
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("_auth_user_id", self.client.session)
