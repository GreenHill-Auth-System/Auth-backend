"""Tests for the signed avatar URLs.

The behaviour under test is what makes one photo appear in all three systems:
the image must load from an origin that does **not** share the auth session
cookie. Same-origin use must keep working exactly as before.
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from authentication.avatar_tokens import (
    AVATAR_SALT,
    avatar_user_from_token,
    issue_avatar_token,
    resolve_avatar_token,
)

from .models import UserProfile

User = get_user_model()

TINY_PNG = "data:image/png;base64,iVBORw0KGgo="


class AvatarTokenTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="ada@greenhillacademy.ac.ug",
            email="ada@greenhillacademy.ac.ug",
            password="unused-in-these-tests",
        )

    def test_round_trips_the_account_id(self):
        token = issue_avatar_token(self.user)

        self.assertEqual(resolve_avatar_token(token), self.user.pk)

    def test_empty_token_resolves_to_nothing(self):
        self.assertIsNone(resolve_avatar_token(""))
        self.assertIsNone(resolve_avatar_token(None))

    def test_tampered_token_resolves_to_nothing(self):
        token = issue_avatar_token(self.user)

        self.assertIsNone(resolve_avatar_token(token[:-4] + "AAAA"))

    def test_token_signed_for_another_purpose_is_refused(self):
        from django.core import signing

        foreign = signing.TimestampSigner(salt="somewhere.else").sign_object(
            {"u": self.user.pk}
        )

        self.assertIsNone(resolve_avatar_token(foreign))

    def test_expired_token_resolves_to_nothing(self):
        token = issue_avatar_token(self.user)
        start = 1_000_000

        with patch("django.core.signing.time.time", return_value=start):
            token = issue_avatar_token(self.user)

        # One day and a second later.
        with patch(
            "django.core.signing.time.time",
            return_value=start + 60 * 60 * 24 + 1,
        ):
            self.assertIsNone(resolve_avatar_token(token))

    def test_token_names_an_account(self):
        token = issue_avatar_token(self.user)

        self.assertEqual(avatar_user_from_token(token), self.user)

    def test_token_for_a_deleted_account_resolves_to_no_user(self):
        token = issue_avatar_token(self.user)
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        self.assertIsNone(avatar_user_from_token(token))

    def test_salt_is_not_the_default_one(self):
        # A wrong salt would make every other project token usable here.
        self.assertTrue(AVATAR_SALT)


class AvatarEndpointTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="ada@greenhillacademy.ac.ug",
            email="ada@greenhillacademy.ac.ug",
            password="unused-in-these-tests",
        )

    def store_avatar(self):
        profile, _created = UserProfile.objects.get_or_create(user=self.user)
        profile.set_avatar_data(TINY_PNG)
        profile.save()
        return profile

    def test_without_a_session_or_token_the_avatar_is_hidden(self):
        self.store_avatar()

        response = self.client.get(reverse("user_avatar"))

        self.assertEqual(response.status_code, 404)

    def test_a_valid_token_serves_the_image_without_a_session(self):
        self.store_avatar()
        token = issue_avatar_token(self.user)

        response = self.client.get(reverse("user_avatar"), {"t": token})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "image/png")

    def test_a_tampered_token_serves_nothing(self):
        self.store_avatar()
        token = issue_avatar_token(self.user)

        response = self.client.get(reverse("user_avatar"), {"t": token[:-4] + "AAAA"})

        self.assertEqual(response.status_code, 404)

    def test_the_session_alone_still_works(self):
        self.store_avatar()
        self.client.force_login(self.user)

        response = self.client.get(reverse("user_avatar"))

        self.assertEqual(response.status_code, 200)

    def test_the_picture_url_carries_a_token(self):
        self.store_avatar()
        self.client.force_login(self.user)

        payload = self.client.get(reverse("user_profile")).json()

        self.assertIn("/auth/avatar/", payload["picture"])
        self.assertIn("t=", payload["picture"])

    def test_the_picture_url_in_the_url_is_enough_on_its_own(self):
        self.store_avatar()
        self.client.force_login(self.user)
        picture = self.client.get(reverse("user_profile")).json()["picture"]

        # Path and query only: this is what another origin would request.
        path = picture.split("/auth/", 1)[1]
        self.client.logout()

        response = self.client.get("/auth/" + path)

        self.assertEqual(response.status_code, 200)
