"""Tests for the shared profile, preferences and avatar endpoints.

The point of these endpoints is that one account looks the same in all three
systems. Most of what is checked below is therefore not "did the row save" but
"does the change reach the places the other systems read" -- `auth.User` for the
name (the OIDC claims read that row) and `/auth/me/` for the identity response
every frontend calls on page load.
"""

import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import AllowedEmail, UserProfile, UserSettings

User = get_user_model()

# The 8-byte PNG signature: a real, decodable image payload small enough to
# keep the test readable.
TINY_PNG = "data:image/png;base64,iVBORw0KGgo="


class ProfileEndpointTests(TestCase):
    def setUp(self):
        AllowedEmail.objects.create(
            email="ada@greenhillacademy.ac.ug",
            role=AllowedEmail.Role.CEO,
            authorized_systems=["EID", "Procurement", "Incident Service Management"],
        )
        self.user = User.objects.create_user(
            username="ada@greenhillacademy.ac.ug",
            email="ada@greenhillacademy.ac.ug",
            password="unused-in-these-tests",
            first_name="Ada",
            last_name="Lovelace",
        )

    def post_json(self, url, payload):
        return self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json",
        )

    def test_requires_authentication(self):
        response = self.client.get(reverse("user_profile"))
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json()["authenticated"])

    def test_get_reports_the_account_as_it_stands(self):
        self.client.force_login(self.user)

        payload = self.client.get(reverse("user_profile")).json()

        self.assertEqual(payload["first_name"], "Ada")
        self.assertEqual(payload["last_name"], "Lovelace")
        self.assertEqual(payload["work_email"], "ada@greenhillacademy.ac.ug")
        self.assertEqual(payload["role"], "CEO")
        self.assertEqual(payload["picture"], "")
        self.assertEqual(payload["avatar_data"], "")

    def test_profile_row_is_created_on_first_read(self):
        self.client.force_login(self.user)
        self.assertFalse(UserProfile.objects.filter(user=self.user).exists())

        self.client.get(reverse("user_profile"))

        self.assertTrue(UserProfile.objects.filter(user=self.user).exists())

    def test_name_is_written_to_the_account_not_a_side_table(self):
        self.client.force_login(self.user)

        self.post_json(reverse("user_profile"), {"first_name": " Augusta ", "last_name": "King "})

        self.user.refresh_from_db()
        # The account row is what the OIDC claims read, so it is the row that
        # has to change for the other two systems to see the new name.
        self.assertEqual(self.user.first_name, "Augusta")
        self.assertEqual(self.user.last_name, "King")
        self.assertEqual(self.user.get_full_name(), "Augusta King")

    def test_name_change_reaches_the_identity_response(self):
        self.client.force_login(self.user)

        session = self.client.session
        session["authenticated_user"] = {
            "email": self.user.email,
            "name": "Ada Lovelace",
            "role": "CEO",
            "authorized_systems": ["EID"],
        }
        session.save()

        self.post_json(reverse("user_profile"), {"first_name": "Augusta", "last_name": "King"})

        identity = self.client.get(reverse("current_user")).json()

        self.assertEqual(identity["user"]["name"], "Augusta King")
        self.assertEqual(identity["user"]["first_name"], "Augusta")

    def test_name_longer_than_the_field_is_rejected(self):
        self.client.force_login(self.user)

        response = self.post_json(reverse("user_profile"), {"first_name": "x" * 151})

        self.assertEqual(response.status_code, 400)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Ada")

    def test_avatar_that_is_not_an_image_is_rejected(self):
        self.client.force_login(self.user)

        response = self.post_json(
            reverse("user_profile"), {"avatar_data": "https://example.com/me.png"}
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(UserProfile.objects.get(user=self.user).has_avatar)

    def test_avatar_that_is_too_large_is_refused(self):
        self.client.force_login(self.user)
        oversized = "data:image/png;base64," + "A" * (UserProfile.MAX_AVATAR_BYTES + 4)

        response = self.post_json(reverse("user_profile"), {"avatar_data": oversized})

        self.assertEqual(response.status_code, 413)
        self.assertFalse(UserProfile.objects.get(user=self.user).has_avatar)

    def test_avatar_url_appears_once_an_image_is_stored(self):
        self.client.force_login(self.user)

        payload = self.post_json(reverse("user_profile"), {"avatar_data": TINY_PNG}).json()

        self.assertTrue(payload["picture"].endswith("/auth/avatar/") is False)
        self.assertIn("/auth/avatar/", payload["picture"])
        # The version parameter is what stops a browser serving yesterday's
        # photo after the image is replaced.
        self.assertIn("?v=", payload["picture"])
        self.assertEqual(payload["avatar_data"], TINY_PNG)

    def test_avatar_bytes_are_served_with_their_image_type(self):
        self.client.force_login(self.user)
        self.post_json(reverse("user_profile"), {"avatar_data": TINY_PNG})

        response = self.client.get(reverse("user_avatar"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "image/png")
        self.assertEqual(response.content, b"\x89PNG\r\n\x1a\n")
        # Private: the image belongs to one account and must not sit in a
        # shared cache.
        self.assertIn("private", response["Cache-Control"])

    def test_avatar_is_absent_for_a_person_who_has_not_set_one(self):
        self.client.force_login(self.user)

        self.assertEqual(self.client.get(reverse("user_avatar")).status_code, 404)

    def test_avatar_is_not_served_to_signed_out_visitors(self):
        self.assertEqual(self.client.get(reverse("user_avatar")).status_code, 404)


class SettingsEndpointTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="ada@greenhillacademy.ac.ug",
            email="ada@greenhillacademy.ac.ug",
            password="unused-in-these-tests",
        )

    def post_json(self, url, payload):
        return self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json",
        )

    def test_requires_authentication(self):
        self.assertEqual(self.client.get(reverse("user_settings")).status_code, 401)

    def test_defaults_are_created_on_first_read(self):
        self.client.force_login(self.user)

        payload = self.client.get(reverse("user_settings")).json()

        self.assertTrue(payload["in_app_notifications"])
        self.assertTrue(payload["email_notifications"])
        self.assertFalse(payload["browser_notifications"])
        self.assertEqual(payload["appearance"], "Light")
        self.assertEqual(payload["time_zone"], "Africa / Kampala")
        self.assertFalse(payload["reduce_motion"])

    def test_changes_are_stored_on_the_account_and_read_back(self):
        self.client.force_login(self.user)

        self.post_json(
            reverse("user_settings"),
            {
                "in_app_notifications": False,
                "browser_notifications": True,
                "appearance": "Dark",
                "time_zone": "Europe / London",
                "reduce_motion": True,
            },
        )

        stored = UserSettings.objects.get(user=self.user)
        self.assertFalse(stored.in_app_notifications)
        self.assertTrue(stored.browser_notifications)
        self.assertEqual(stored.appearance, "Dark")
        self.assertEqual(stored.time_zone, "Europe / London")
        self.assertTrue(stored.reduce_motion)

        # Reading back is the same as reading it in any of the other systems.
        payload = self.client.get(reverse("user_settings")).json()
        self.assertEqual(payload["appearance"], "Dark")

    def test_booleans_arrive_as_real_booleans(self):
        self.client.force_login(self.user)

        payload = self.post_json(
            reverse("user_settings"), {"in_app_notifications": False}
        ).json()

        self.assertIs(payload["in_app_notifications"], False)

    def test_unknown_appearance_is_rejected(self):
        self.client.force_login(self.user)

        response = self.post_json(reverse("user_settings"), {"appearance": "Neon"})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(UserSettings.objects.get(user=self.user).appearance, "Light")

    def test_time_zone_longer_than_the_field_is_rejected(self):
        self.client.force_login(self.user)

        response = self.post_json(reverse("user_settings"), {"time_zone": "z" * 65})

        self.assertEqual(response.status_code, 400)
