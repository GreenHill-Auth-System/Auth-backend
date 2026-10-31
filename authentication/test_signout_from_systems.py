"""Signing out *from* EID, PMS or ISMP.

The three systems cannot share this service's cookie reliably -- ``onrender.com``
is a public suffix, so a call from one of their pages is a third-party request
and the browser may withhold the cookie even with ``SameSite=None``. A sign-out
that cannot identify the caller is worse than no sign-out at all: it answers 200
and revokes nothing, so the relying party keeps a working access token.

These tests pin down the two things that make the button actually work:

* a live access token is enough to identify whose tokens to destroy, so a
  relying party's backend can revoke server-to-server;
* the response says where to send the browser, so the person lands on the
  sign-in page and gets a fresh token next time instead of a dead shell.
"""

import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_refresh_token_model,
)

from .tokens import user_from_bearer_token
from .views import get_frontend_url

User = get_user_model()
Application = get_application_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()


def make_user(email):
    return User.objects.create_user(username=email, email=email, password="pw-for-tests-123")


def make_application(name="GreenHill EID"):
    return Application.objects.create(
        name=name,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://eid.example/callback",
        skip_authorization=True,
    )


class BearerIdentityTests(TestCase):
    def setUp(self):
        self.user = make_user("cnmusisi@greenhillacademy.ac.ug")
        self.application = make_application()

    def _grant(self, user=None, token="access-1", expires=None):
        user = user or self.user

        refresh = RefreshToken.objects.create(
            user=user,
            application=self.application,
            token="refresh-" + token,
        )
        access = AccessToken.objects.create(
            user=user,
            application=self.application,
            token=token,
            expires=expires or (timezone.now() + timedelta(hours=1)),
            source_refresh_token=refresh,
        )
        return access

    def sign_out(self, token):
        return self.client.post(
            "/auth/logout/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

    def test_a_live_token_identifies_the_account(self):
        access = self._grant()

        self.assertEqual(user_from_bearer_token(access.token), self.user)

    def test_a_bearer_token_signs_the_person_out_without_a_cookie(self):
        access = self._grant()

        response = self.sign_out(access.token)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["access_tokens_revoked"], 1)
        self.assertEqual(response.json()["refresh_tokens_revoked"], 1)
        self.assertEqual(AccessToken.objects.filter(user=self.user).count(), 0)

    def test_the_token_stops_working_afterwards(self):
        access = self._grant()
        self.sign_out(access.token)

        # A replay of the same header must not identify anybody, or a stale
        # value could force repeated sign-outs.
        self.assertIsNone(user_from_bearer_token(access.token))

    def test_an_expired_token_identifies_nobody(self):
        self._grant(expires=timezone.now() - timedelta(minutes=1))

        self.assertIsNone(user_from_bearer_token("access-1"))

    def test_an_inactive_account_identifies_nobody(self):
        access = self._grant()
        User.objects.filter(pk=self.user.pk).update(is_active=False)

        self.assertIsNone(user_from_bearer_token(access.token))

    def test_an_unknown_token_identifies_nobody(self):
        self.assertIsNone(user_from_bearer_token("not-a-token"))
        self.assertIsNone(user_from_bearer_token(""))

    def test_a_non_bearer_scheme_is_ignored(self):
        access = self._grant()

        response = self.client.post(
            "/auth/logout/",
            HTTP_AUTHORIZATION=f"Basic {access.token}",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["access_tokens_revoked"], 0)
        self.assertEqual(AccessToken.objects.filter(user=self.user).count(), 1)

    def test_the_session_wins_over_a_token_from_somebody_else(self):
        other = make_user("other@greenhillacademy.ac.ug")
        theirs = self._grant(user=other, token="other-access")

        self.client.force_login(self.user)
        self._grant(token="mine")

        self.sign_out(theirs.token)

        # The browser is signed in as `self.user`, so that is whose credentials
        # go; a token belonging to a second account must not redirect the
        # revocation at somebody else.
        self.assertEqual(AccessToken.objects.filter(user=other).count(), 1)
        self.assertEqual(AccessToken.objects.filter(user=self.user).count(), 0)

    def test_signing_out_everywhere_also_accepts_a_token(self):
        access = self._grant()

        response = self.client.post(
            "/auth/logout-everywhere/",
            HTTP_AUTHORIZATION=f"Bearer {access.token}",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(AccessToken.objects.filter(user=self.user).count(), 0)


class RedirectAfterSignOutTests(TestCase):
    def setUp(self):
        self.user = make_user("ada@greenhillacademy.ac.ug")

    def post_json(self, url, payload):
        return self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json",
        )

    def test_the_default_lands_on_the_sign_in_page(self):
        self.client.force_login(self.user)

        payload = self.post_json("/auth/logout/", {}).json()

        self.assertEqual(payload["redirect_to"], f"{get_frontend_url()}/")

    def test_a_trusted_next_is_honoured(self):
        self.client.force_login(self.user)
        target = "https://greenhill-eid-frontend.onrender.com/"

        payload = self.post_json("/auth/logout/", {"next": target}).json()

        self.assertEqual(payload["redirect_to"], target)

    def test_an_untrusted_next_is_dropped(self):
        self.client.force_login(self.user)

        payload = self.post_json(
            "/auth/logout/",
            {"next": "https://evil.example.com/steal"},
        ).json()

        self.assertEqual(payload["redirect_to"], f"{get_frontend_url()}/")

    def test_a_relative_next_is_dropped(self):
        self.client.force_login(self.user)

        payload = self.post_json("/auth/logout/", {"next": "/signed-out"}).json()

        self.assertEqual(payload["redirect_to"], f"{get_frontend_url()}/")

    def test_the_cookie_is_gone_afterwards(self):
        self.client.force_login(self.user)

        self.post_json("/auth/logout/", {})

        self.assertEqual(self.client.get("/auth/me/").status_code, 401)

    def test_signing_out_everywhere_reports_a_target_too(self):
        self.client.force_login(self.user)

        payload = self.post_json("/auth/logout-everywhere/", {}).json()

        self.assertEqual(payload["redirect_to"], f"{get_frontend_url()}/")

    def test_the_redirect_view_still_honours_next(self):
        self.client.force_login(self.user)

        response = self.client.get(
            "/auth/logout-redirect/",
            {"next": "https://greenhill-eid-frontend.onrender.com/"},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response["Location"],
            "https://greenhill-eid-frontend.onrender.com/",
        )
