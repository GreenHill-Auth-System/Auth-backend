"""Tests for the identity record: email as key, Google subject as binding.

Covers ``authentication.users`` (the rules) and the parts of
``google_callback`` that enforce them (the plumbing).
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.urls import reverse

from authentication.models import GoogleIdentity
from authentication.users import (
    find_user_by_email,
    get_or_create_user_by_email,
    google_claims_are_trustworthy,
    link_google_identity,
    normalize_email,
    resolve_google_user,
)

GREENHILL_EMAIL = "employee@greenhillacademy.ac.ug"
GREENHILL_SUB = "google-sub-employee"
FRONTEND = "http://localhost:5173"


def claims(**overrides):
    """A verified Google id_token payload for a GreenHill account."""
    payload = {
        "email": GREENHILL_EMAIL,
        "name": "GreenHill Employee",
        "sub": GREENHILL_SUB,
        "email_verified": True,
        "hd": "greenhillacademy.ac.ug",
    }
    payload.update(overrides)
    return payload


class NormalizeEmailTests(TestCase):

    def test_strips_whitespace_and_lowercases(self):
        self.assertEqual(
            normalize_email("  ReFactory@GreenHillAcademy.ac.ug  "),
            "refactory@greenhillacademy.ac.ug",
        )

    def test_none_becomes_empty_string(self):
        self.assertEqual(normalize_email(None), "")

    def test_empty_string_stays_empty(self):
        self.assertEqual(normalize_email(""), "")


class FindUserByEmailTests(TestCase):

    def test_matches_regardless_of_case(self):
        user = get_user_model().objects.create(
            username="stored",
            email="Employee@GreenhillAcademy.ac.ug",
        )

        self.assertEqual(
            find_user_by_email("employee@greenhillacademy.ac.ug"),
            user,
        )

    def test_blank_email_never_matches(self):
        # Many staff accounts have a blank email; matching on "" would let any
        # of them be returned as somebody's identity.
        get_user_model().objects.create(username="staff-only", email="")

        self.assertIsNone(find_user_by_email(""))
        self.assertIsNone(find_user_by_email("   "))
        self.assertIsNone(find_user_by_email(None))

    def test_unknown_email_returns_none(self):
        self.assertIsNone(find_user_by_email("nobody@greenhillacademy.ac.ug"))


class GetOrCreateUserByEmailTests(TestCase):

    def test_creates_user_with_email_as_username(self):
        user, created = get_or_create_user_by_email(
            GREENHILL_EMAIL,
            "GreenHill Employee",
        )

        self.assertTrue(created)
        self.assertEqual(user.email, GREENHILL_EMAIL)
        self.assertEqual(user.username, GREENHILL_EMAIL)
        self.assertEqual(user.first_name, "GreenHill Employee")

    def test_created_user_has_no_usable_password(self):
        user, _ = get_or_create_user_by_email(GREENHILL_EMAIL)

        self.assertFalse(user.has_usable_password())

    def test_reuses_existing_user_across_cases(self):
        User = get_user_model()
        existing = User.objects.create(
            username="existing",
            email=GREENHILL_EMAIL,
        )

        user, created = get_or_create_user_by_email(
            "  EMPLOYEE@GreenhillAcademy.ac.ug  "
        )

        self.assertFalse(created)
        self.assertEqual(user.pk, existing.pk)
        self.assertEqual(User.objects.count(), 1)

    def test_repeated_calls_do_not_duplicate(self):
        get_or_create_user_by_email(GREENHILL_EMAIL)
        get_or_create_user_by_email(GREENHILL_EMAIL)

        self.assertEqual(get_user_model().objects.count(), 1)


class EmailUniquenessConstraintTests(TestCase):

    def test_database_rejects_two_users_with_same_email(self):
        User = get_user_model()
        User.objects.create(username="first", email=GREENHILL_EMAIL)

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                User.objects.create(
                    username="second",
                    email=GREENHILL_EMAIL.upper(),
                )

    def test_database_allows_many_blank_emails(self):
        User = get_user_model()
        User.objects.create(username="blank-1", email="")
        User.objects.create(username="blank-2", email="")

        self.assertEqual(User.objects.filter(email="").count(), 2)


class GoogleClaimsTrustTests(TestCase):

    def test_verified_greenhill_claims_are_accepted(self):
        ok, reason = google_claims_are_trustworthy(claims())

        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_verified_claim_without_hosted_domain_is_accepted(self):
        payload = claims()
        payload.pop("hd")

        ok, reason = google_claims_are_trustworthy(payload)

        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_missing_email_verified_is_rejected(self):
        payload = claims()
        payload.pop("email_verified")

        ok, reason = google_claims_are_trustworthy(payload)

        self.assertFalse(ok)
        self.assertEqual(reason, "email_not_verified")

    def test_false_email_verified_is_rejected(self):
        ok, reason = google_claims_are_trustworthy(
            claims(email_verified=False)
        )

        self.assertFalse(ok)
        self.assertEqual(reason, "email_not_verified")

    def test_string_true_is_not_accepted(self):
        ok, _ = google_claims_are_trustworthy(
            claims(email_verified="true")
        )

        self.assertFalse(ok)

    def test_other_hosted_domain_is_rejected(self):
        ok, reason = google_claims_are_trustworthy(
            claims(hd="other-school.org")
        )

        self.assertFalse(ok)
        self.assertEqual(reason, "wrong_hosted_domain")

    def test_hosted_domain_comparison_ignores_case(self):
        ok, _ = google_claims_are_trustworthy(
            claims(hd="GreenHillAcademy.ac.ug")
        )

        self.assertTrue(ok)


class LinkGoogleIdentityTests(TestCase):

    def setUp(self):
        self.user, _ = get_or_create_user_by_email(GREENHILL_EMAIL)

    def test_records_identity(self):
        identity = link_google_identity(self.user, claims())

        self.assertEqual(identity.user_id, self.user.pk)
        self.assertEqual(identity.google_sub, GREENHILL_SUB)
        self.assertEqual(identity.google_email, GREENHILL_EMAIL)
        self.assertEqual(identity.hosted_domain, "greenhillacademy.ac.ug")
        self.assertTrue(identity.email_verified)

    def test_second_sign_in_updates_the_same_row(self):
        link_google_identity(self.user, claims())
        link_google_identity(
            self.user,
            claims(email="Employee2@greenhillacademy.ac.ug"),
        )

        self.assertEqual(GoogleIdentity.objects.count(), 1)
        self.assertEqual(
            GoogleIdentity.objects.get().google_email,
            "employee2@greenhillacademy.ac.ug",
        )

    def test_subject_already_owned_by_another_user_is_refused(self):
        link_google_identity(self.user, claims())

        intruder, _ = get_or_create_user_by_email(
            "someone.else@greenhillacademy.ac.ug"
        )

        with self.assertRaises(ValueError):
            link_google_identity(intruder, claims())

        self.assertEqual(GoogleIdentity.objects.count(), 1)
        self.assertEqual(
            GoogleIdentity.objects.get().user_id,
            self.user.pk,
        )

    def test_missing_subject_is_refused(self):
        payload = claims()
        payload.pop("sub")

        with self.assertRaises(ValueError):
            link_google_identity(self.user, payload)


class ResolveGoogleUserTests(TestCase):

    def test_new_subject_creates_user_and_identity(self):
        user, created = resolve_google_user(claims())

        self.assertTrue(created)
        self.assertEqual(user.email, GREENHILL_EMAIL)
        self.assertEqual(GoogleIdentity.objects.get().user_id, user.pk)

    def test_known_subject_reuses_user(self):
        first, _ = resolve_google_user(claims())
        second, created = resolve_google_user(claims())

        self.assertFalse(created)
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(get_user_model().objects.count(), 1)

    def test_known_subject_follows_an_email_rename(self):
        user, _ = resolve_google_user(claims())

        renamed, created = resolve_google_user(
            claims(email="employee.renamed@greenhillacademy.ac.ug")
        )

        self.assertFalse(created)
        self.assertEqual(renamed.pk, user.pk)
        self.assertEqual(
            renamed.email, "employee.renamed@greenhillacademy.ac.ug"
        )
        self.assertEqual(get_user_model().objects.count(), 1)

    def test_address_owned_by_another_account_is_refused(self):
        resolve_google_user(claims())
        get_or_create_user_by_email("someone.else@greenhillacademy.ac.ug")

        with self.assertRaises(ValueError):
            resolve_google_user(
                claims(email="someone.else@greenhillacademy.ac.ug")
            )

        # No third account, no second identity, original binding intact.
        self.assertEqual(get_user_model().objects.count(), 2)
        self.assertEqual(GoogleIdentity.objects.count(), 1)
        self.assertEqual(
            GoogleIdentity.objects.get().user.email, GREENHILL_EMAIL
        )

    def test_rename_onto_a_taken_address_is_refused(self):
        resolve_google_user(claims())
        get_or_create_user_by_email("taken@greenhillacademy.ac.ug")

        with self.assertRaises(ValueError):
            resolve_google_user(
                claims(email="taken@greenhillacademy.ac.ug")
            )


class GoogleCallbackIdentityTests(TestCase):
    """The callback must refuse unverified or foreign Google identities."""

    def _run_callback(self, payload):
        session = self.client.session
        session["google_oauth_state"] = "test-state"
        session["google_code_verifier"] = "test-verifier"
        session.save()

        with patch("authentication.views.os.getenv") as mock_getenv, \
                patch("authentication.views.Flow") as mock_flow_class, \
                patch(
                    "authentication.views.id_token.verify_oauth2_token"
                ) as mock_verify_token:
            mock_getenv.side_effect = lambda key, default=None: {
                "GOOGLE_CLIENT_ID": "test-client-id",
                "GOOGLE_CLIENT_SECRET": "test-client-secret",
                "GOOGLE_REDIRECT_URI": (
                    "http://localhost:8000/auth/google/callback/"
                ),
                "FRONTEND_URL": FRONTEND,
            }.get(key, default)

            flow = mock_flow_class.from_client_config.return_value
            flow.credentials.id_token = "mock-id-token"

            mock_verify_token.return_value = payload

            return self.client.get(
                reverse("google_callback"),
                {"state": "test-state", "code": "test-code"},
            )

    def test_verified_identity_is_recorded_on_sign_in(self):
        response = self._run_callback(claims())

        self.assertEqual(
            response.url, f"{FRONTEND}/workspaces?login=success"
        )

        identity = GoogleIdentity.objects.get()
        self.assertEqual(identity.google_sub, GREENHILL_SUB)
        self.assertEqual(
            identity.user.email, GREENHILL_EMAIL
        )

    def test_unverified_email_is_rejected_and_creates_no_user(self):
        response = self._run_callback(claims(email_verified=False))

        self.assertEqual(
            response.url, f"{FRONTEND}/?error=email_not_verified"
        )
        self.assertEqual(get_user_model().objects.count(), 0)
        self.assertEqual(GoogleIdentity.objects.count(), 0)

    def test_foreign_hosted_domain_is_rejected(self):
        response = self._run_callback(claims(hd="other-school.org"))

        self.assertEqual(
            response.url, f"{FRONTEND}/?error=wrong_hosted_domain"
        )
        self.assertEqual(get_user_model().objects.count(), 0)

    def test_address_owned_by_another_account_is_rejected(self):
        # A Google subject can never be used to take over an address that is
        # already a different local account.
        User = get_user_model()

        first, _ = resolve_google_user(claims())
        second, _ = get_or_create_user_by_email(
            "second@greenhillacademy.ac.ug"
        )

        response = self._run_callback(
            claims(email="second@greenhillacademy.ac.ug")
        )

        self.assertEqual(
            response.url, f"{FRONTEND}/?error=identity_conflict"
        )
        self.assertEqual(
            GoogleIdentity.objects.get().user_id, first.pk
        )
        self.assertEqual(
            User.objects.get(email=GREENHILL_EMAIL).pk, first.pk
        )
        self.assertEqual(
            User.objects.get(email="second@greenhillacademy.ac.ug").pk,
            second.pk,
        )

    def test_repeated_sign_in_does_not_duplicate_the_user(self):
        self._run_callback(claims())
        self.client.cookies.clear()
        self._run_callback(claims())

        self.assertEqual(get_user_model().objects.count(), 1)
        self.assertEqual(GoogleIdentity.objects.count(), 1)


class ManualLoginEmailLookupTests(TestCase):

    def test_uppercase_email_authenticates_stored_lowercase_account(self):
        get_user_model().objects.create_user(
            username=GREENHILL_EMAIL,
            email=GREENHILL_EMAIL,
            password="correct-horse",
        )

        response = self.client.post(
            reverse("manual_login"),
            {
                "email": "Employee@GreenHillAcademy.ac.ug",
                "password": "correct-horse",
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["authenticated"])

    def test_blank_email_is_never_authenticated(self):
        get_user_model().objects.create_user(
            username="staff-only",
            email="",
            password="correct-horse",
        )

        response = self.client.post(
            reverse("manual_login"),
            {"email": "", "password": "correct-horse"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["authenticated"])
