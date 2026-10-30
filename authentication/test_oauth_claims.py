from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.test import TestCase

from .models import AllowedEmail, UserProfile
from .oauth_validators import GreenHillOAuth2Validator

TINY_PNG = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmM"
    "IQAAAABJRU5ErkJggg=="
)


def _request_for(user):
    """A stand-in request: the claims only need the user and a URL builder."""
    return SimpleNamespace(
        user=user,
        build_absolute_uri=lambda path: f"https://auth.example.test{path}",
    )


class OAuthClaimsTests(TestCase):
    def _claims_for(self, email):
        request = _request_for(
            SimpleNamespace(
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


class PictureClaimTests(TestCase):
    """The ``picture`` claim, so a relying party can draw the real avatar.

    Without it the three systems can only render initials, even after the
    person has uploaded a photo in the account settings.
    """

    def test_picture_is_gated_behind_the_profile_scope(self):
        self.assertEqual(
            GreenHillOAuth2Validator.oidc_claim_scope["picture"], "profile"
        )

    def test_picture_is_listed_in_discovery(self):
        claims = GreenHillOAuth2Validator().get_discovery_claims(
            _request_for(SimpleNamespace(email="someone@greenhillacademy.ac.ug"))
        )
        self.assertIn("picture", claims)

    def test_picture_is_empty_when_no_avatar_is_stored(self):
        user = get_user_model().objects.create_user(
            username="noavatar@greenhillacademy.ac.ug",
            email="noavatar@greenhillacademy.ac.ug",
        )
        claims = GreenHillOAuth2Validator().get_additional_claims()
        self.assertEqual(claims["picture"](_request_for(user)), "")

    def test_picture_points_at_the_avatar_once_one_is_stored(self):
        user = get_user_model().objects.create_user(
            username="avatar@greenhillacademy.ac.ug",
            email="avatar@greenhillacademy.ac.ug",
        )
        profile = UserProfile.objects.create(user=user)
        profile.set_avatar_data(TINY_PNG)
        profile.save()

        claims = GreenHillOAuth2Validator().get_additional_claims()
        picture = claims["picture"](_request_for(user))

        self.assertTrue(picture.startswith("https://auth.example.test/"))
        self.assertIn("/auth/avatar/", picture)
        # The cache-busting parameter, so a replaced avatar is picked up.
        self.assertIn("?v=", picture)