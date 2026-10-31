"""No answer about a person may be reused from a cache.

The forward arrow is the browser's memory: a restored page does not ask the
server again, so whatever it kept from before a sign-out is what the person
sees. A cached ``{"authenticated": true}`` is therefore not a cosmetic problem,
it is a way back in without credentials.

The auth frontend already sends ``cache: "no-store"`` on its one identity fetch.
The three systems do not -- ``fetchCurrentUser`` in EID uses axios with no cache
directive -- so the header has to arrive with the answer, because a caller that
forgets the flag must still not be cacheable.
"""

import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from authentication.cache_headers import NO_STORE
from authentication.models import AllowedEmail

User = get_user_model()


class NoStoreIdentityTests(TestCase):
    def setUp(self):
        AllowedEmail.objects.create(
            email="ada@greenhillacademy.ac.ug",
            role=AllowedEmail.Role.CEO,
            authorized_systems=["EID"],
        )
        self.user = User.objects.create_user(
            username="ada@greenhillacademy.ac.ug",
            email="ada@greenhillacademy.ac.ug",
            password="unused-in-these-tests",
        )
        self.client.force_login(self.user)

        session = self.client.session
        session["authenticated_user"] = {
            "email": self.user.email,
            "name": "Ada",
            "role": "CEO",
            "authorized_systems": ["EID"],
        }
        session.save()

    def assert_not_cacheable(self, response):
        self.assertEqual(response["Cache-Control"], NO_STORE)
        self.assertEqual(response["Pragma"], "no-cache")
        self.assertEqual(response["Expires"], "0")
        # Without this a shared cache that ignores `no-store` could hand one
        # person's answer to another.
        self.assertIn("Cookie", response["Vary"])

    def test_the_identity_answer_is_not_cacheable(self):
        response = self.client.get(reverse("current_user"))

        self.assertEqual(response.status_code, 200)
        self.assert_not_cacheable(response)

        # The header work must not change the payload the systems parse.
        self.assertEqual(
            json.loads(response.content)["user"]["email"],
            "ada@greenhillacademy.ac.ug",
        )

    def test_a_signed_out_identity_answer_is_not_cacheable(self):
        # Cached in either direction is wrong: a stored 401 would outlive the
        # next successful sign-in.
        self.client.logout()

        response = self.client.get(reverse("current_user"))

        self.assertEqual(response.status_code, 401)
        self.assert_not_cacheable(response)

    def test_the_profile_and_settings_answers_are_not_cacheable(self):
        for url_name in ("user_profile", "user_settings", "session_list"):
            with self.subTest(url_name=url_name):
                self.assert_not_cacheable(self.client.get(reverse(url_name)))

    def test_the_csrf_bootstrap_answer_is_not_cacheable(self):
        self.assert_not_cacheable(self.client.get(reverse("csrf_token")))

    def test_sign_out_answers_are_not_cacheable(self):
        response = self.client.post(reverse("sign_out"))

        self.assertEqual(response.status_code, 200)
        self.assert_not_cacheable(response)

    def test_the_post_sign_out_redirect_is_not_cacheable(self):
        # The redirect target is a history entry of its own. If the browser
        # replays it from cache it never reaches the server, so nothing tells
        # the app the session is gone.
        response = self.client.get(reverse("sign_out_redirect"))

        self.assertEqual(response.status_code, 302)
        self.assert_not_cacheable(response)


class AvatarStaysCacheableTests(TestCase):
    """The avatar is a picture, not a claim about who is signed in.

    It is already marked ``private, max-age=300`` by its own view; marking it
    ``no-store`` as well would re-download the same bytes on every render and
    change nothing about whether the person is signed in.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="ada@greenhillacademy.ac.ug",
            email="ada@greenhillacademy.ac.ug",
            password="unused-in-these-tests",
        )
        self.client.force_login(self.user)

    def test_the_avatar_keeps_its_own_cache_policy(self):
        import base64

        from authentication.models import UserProfile

        profile, _ = UserProfile.objects.get_or_create(user=self.user)
        profile.set_avatar_data(
            "data:image/png;base64," + base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"0" * 64).decode()
        )
        profile.save()

        response = self.client.get(reverse("user_avatar"))

        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response["Cache-Control"], NO_STORE)
        self.assertIn("private", response["Cache-Control"])


class UnrelatedPathsAreUntouchedTests(TestCase):
    def test_a_path_outside_the_identity_prefixes_keeps_its_headers(self):
        # `CommonMiddleware` is in front of the middleware under test; a plain
        # 404 for an unrelated path must not gain identity headers.
        response = self.client.get("/not-an-auth-path/")

        self.assertEqual(response.status_code, 404)
        self.assertNotIn("Pragma", response.headers)

    def test_documenting_the_rule_keeps_the_list_short(self):
        # A long list of exemptions is how something private ends up cacheable
        # again. Only files belong here.
        from authentication.cache_headers import EXEMPT_PREFIXES

        self.assertEqual(EXEMPT_PREFIXES, ("/auth/avatar/",))
