"""Tests for OIDC scope enforcement.

The hole this closes: the toolkit checks that a *client* is allowed to ask for
``eid``, but on its own it never checks that the *person* is allowed to hold
it. Without ``GreenHillOAuth2Validator.validate_scopes`` any signed-in account
could mint a token carrying ``eid`` and every downstream permission check in
the three systems would be meaningless.
"""

from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.test import TestCase
from oauth2_provider.models import get_application_model

from .access import split_requested_scopes
from .models import AllowedEmail
from .oauth_validators import GreenHillOAuth2Validator

User = get_user_model()
Application = get_application_model()


def make_user(email="cnmusisi@greenhillacademy.ac.ug"):
    return User.objects.create_user(username=email, email=email, password="pw-for-tests-123")


def make_application():
    return Application.objects.create(
        name="GreenHill EID",
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://eid.example/callback",
        skip_authorization=True,
    )


class SplitRequestedScopesTests(TestCase):
    def setUp(self):
        AllowedEmail.objects.create(
            email="cnmusisi@greenhillacademy.ac.ug",
            role=AllowedEmail.Role.MANAGER,
            authorized_systems=[
                AllowedEmail.System.EID,
                AllowedEmail.System.PROCUREMENT,
            ],
        )

    def test_granted_scopes_are_allowed(self):
        allowed, denied = split_requested_scopes(
            "cnmusisi@greenhillacademy.ac.ug",
            ["openid", "profile", "email", "eid", "procurement"],
        )
        self.assertEqual(denied, set())
        self.assertEqual(
            allowed,
            {"openid", "profile", "email", "eid", "procurement"},
        )

    def test_ungranted_scope_is_denied(self):
        allowed, denied = split_requested_scopes(
            "cnmusisi@greenhillacademy.ac.ug",
            ["openid", "eid", "incident"],
        )
        self.assertEqual(denied, {"incident"})
        self.assertNotIn("incident", allowed)

    def test_unlisted_address_gets_base_scopes_only(self):
        allowed, denied = split_requested_scopes(
            "nobody@greenhillacademy.ac.ug",
            ["openid", "profile", "eid"],
        )
        self.assertEqual(allowed, {"openid", "profile"})
        self.assertEqual(denied, {"eid"})

    def test_blank_scope_entries_are_ignored(self):
        allowed, denied = split_requested_scopes(
            "cnmusisi@greenhillacademy.ac.ug",
            ["openid", "", None],
        )
        self.assertEqual(allowed, {"openid"})
        self.assertEqual(denied, set())

    def test_inactive_grant_withholds_scopes(self):
        AllowedEmail.objects.filter(
            email="cnmusisi@greenhillacademy.ac.ug"
        ).update(is_active=False)
        _, denied = split_requested_scopes(
            "cnmusisi@greenhillacademy.ac.ug",
            ["eid"],
        )
        self.assertEqual(denied, {"eid"})


class ValidateScopesTests(TestCase):
    def setUp(self):
        self.application = make_application()
        self.validator = GreenHillOAuth2Validator()

    def _request(self, user):
        return SimpleNamespace(user=user)

    def _validate(self, user, scopes):
        return self.validator.validate_scopes(
            client_id=self.application.client_id,
            scopes=scopes,
            client=self.application,
            request=self._request(user),
        )

    def test_signed_in_user_with_the_grant_is_allowed(self):
        user = make_user()
        AllowedEmail.objects.create(
            email=user.email,
            authorized_systems=[AllowedEmail.System.EID],
        )
        self.assertTrue(self._validate(user, ["openid", "eid"]))

    def test_signed_in_user_without_the_grant_is_refused(self):
        user = make_user()
        self.assertFalse(self._validate(user, ["openid", "eid"]))

    def test_unlisted_user_can_still_sign_in(self):
        user = make_user()
        self.assertTrue(self._validate(user, ["openid", "profile", "email"]))

    def test_anonymous_token_exchange_is_not_rechecked(self):
        # During the token request there is no session user; the grant was
        # already authorised at /o/authorize/.
        anonymous = SimpleNamespace(is_authenticated=False, email="")
        self.assertTrue(self._validate(anonymous, ["openid", "eid"]))

    def test_scope_the_client_cannot_request_is_refused(self):
        user = make_user()
        AllowedEmail.objects.create(
            email=user.email,
            authorized_systems=[AllowedEmail.System.EID],
        )
        self.assertFalse(self._validate(user, ["not-a-real-scope"]))

    def test_manager_with_two_systems_gets_both(self):
        user = make_user()
        AllowedEmail.objects.create(
            email=user.email,
            authorized_systems=[
                AllowedEmail.System.EID,
                AllowedEmail.System.INCIDENT,
            ],
        )
        self.assertTrue(
            self._validate(user, ["openid", "eid", "incident"])
        )
        self.assertFalse(
            self._validate(user, ["openid", "eid", "procurement"])
        )
