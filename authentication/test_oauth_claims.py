from types import SimpleNamespace

from django.test import TestCase

from .models import AllowedEmail
from .oauth_validators import GreenHillOAuth2Validator


class OAuthClaimsTests(TestCase):
    def _claims_for(self, email):
        request = SimpleNamespace(
            user=SimpleNamespace(
                email=email,
                first_name="",
                last_name="",
                username=email,
            )
        )
        claims = GreenHillOAuth2Validator().get_additional_claims()
        return {key: fn(request) for key, fn in claims.items()}

    def test_listed_user_gets_role_and_systems(self):
        AllowedEmail.objects.create(
            email="boss@greenhillacademy.ac.ug",
            role=AllowedEmail.Role.MANAGER,
            authorized_systems=["EID", "Procurement"],
        )
        claims = self._claims_for("boss@greenhillacademy.ac.ug")
        self.assertEqual(claims["role"], "Manager")
        self.assertEqual(claims["authorized_systems"], ["EID", "Procurement"])

    def test_unlisted_user_gets_no_systems(self):
        claims = self._claims_for("nobody@greenhillacademy.ac.ug")
        self.assertEqual(claims["authorized_systems"], [])