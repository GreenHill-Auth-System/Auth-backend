"""Tests for the fields that keep three systems showing one person.

Every relying party keeps a copy of the profile -- EID, for instance, stores a
local ``auth_user`` row built from the token claims. A copy is only harmless if
the system can tell when it has gone stale, and if nothing it copies is ever
blank when it does not need to be.

So these cover two promises:

* ``profile_version`` moves on every profile write, including a rename, so a
  copy can be invalidated without polling the whole profile;
* the ``name`` claim is never empty for an account that has an email address.
"""

import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from types import SimpleNamespace

from .models import AllowedEmail, profile_version
from .oauth_validators import GreenHillOAuth2Validator

User = get_user_model()


def _request_for(user):
    return SimpleNamespace(
        user=user,
        build_absolute_uri=lambda path: f"https://auth.example.test{path}",
    )


class ProfileVersionTests(TestCase):
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

    def post_json(self, url, payload):
        return self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json",
        )

    def test_an_account_with_no_profile_row_reports_zero(self):
        self.assertEqual(profile_version(self.user), 0)

    def test_reading_the_profile_issues_a_version(self):
        payload = self.client.get(reverse("user_profile")).json()

        self.assertGreater(payload["profile_version"], 0)

    def test_a_rename_moves_the_version(self):
        before = self.client.get(reverse("user_profile")).json()["profile_version"]

        after = self.post_json(
            reverse("user_profile"),
            {"first_name": "Ada", "last_name": "Lovelace"},
        ).json()["profile_version"]

        self.assertGreater(after, before)

    def test_the_identity_response_carries_the_version(self):
        self.post_json(reverse("user_profile"), {"first_name": "Ada"})

        session = self.client.session
        session["authenticated_user"] = {
            "email": self.user.email,
            "name": "Ada",
            "role": "CEO",
            "authorized_systems": ["EID"],
        }
        session.save()

        payload = self.client.get(reverse("current_user")).json()

        self.assertIn("profile_version", payload["user"])
        self.assertGreater(payload["user"]["profile_version"], 0)

    def test_the_claim_matches_the_endpoint(self):
        self.post_json(reverse("user_profile"), {"first_name": "Ada"})

        claims = GreenHillOAuth2Validator().get_additional_claims()
        request = _request_for(User.objects.get(pk=self.user.pk))

        self.assertEqual(
            claims["profile_version"](request),
            self.client.get(reverse("user_profile")).json()["profile_version"],
        )


class NameClaimTests(TestCase):
    def _claims_for(self, first_name, last_name):
        user = SimpleNamespace(
            email="noname@greenhillacademy.ac.ug",
            first_name=first_name,
            last_name=last_name,
            username="noname@greenhillacademy.ac.ug",
        )
        return {
            key: fn(_request_for(user))
            for key, fn in GreenHillOAuth2Validator().get_additional_claims().items()
        }

    def test_a_full_name_is_used(self):
        self.assertEqual(self._claims_for("Ada", "Lovelace")["name"], "Ada Lovelace")

    def test_a_first_name_alone_is_used(self):
        self.assertEqual(self._claims_for("Ada", "")["name"], "Ada")

    def test_no_name_falls_back_to_the_address(self):
        # An empty header looks like a broken system; the address is always
        # available and always identifies the person unambiguously.
        self.assertEqual(
            self._claims_for("", "")["name"],
            "noname@greenhillacademy.ac.ug",
        )

    def test_the_discovery_documents_the_version_claim(self):
        request = _request_for(
            SimpleNamespace(email="a@greenhillacademy.ac.ug")
        )

        self.assertIn(
            "profile_version",
            GreenHillOAuth2Validator().get_discovery_claims(request),
        )
