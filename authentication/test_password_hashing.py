"""Tests for the password hashing configuration.

Sign-in latency is dominated by the password hash, so the choice of algorithm
and its parameters is a behavioural contract, not an implementation detail:

* new passwords must be stored with Argon2id, not PBKDF2;
* a password already stored with PBKDF2 must still verify, otherwise deploying
  this change would lock every existing user out;
* Django must be willing to re-hash a PBKDF2 value on the next sign-in, which
  is how the migration to Argon2id happens without a data migration.

These tests do not assert timings -- wall-clock limits are noise on shared CI
runners -- but they do assert the algorithm, which is what controls the cost.
"""

from django.contrib.auth import authenticate
from django.contrib.auth.hashers import (
    PBKDF2PasswordHasher,
    check_password,
    identify_hasher,
    make_password,
)
from django.contrib.auth.models import User
from django.test import TestCase

from authentication.password_hashers import GreenHillArgon2PasswordHasher


class PasswordHashingConfigurationTests(TestCase):
    def test_argon2_is_the_primary_hasher(self):
        from django.conf import settings

        self.assertEqual(
            settings.PASSWORD_HASHERS[0],
            "authentication.password_hashers."
            "GreenHillArgon2PasswordHasher",
        )

    def test_new_passwords_use_argon2id(self):
        encoded = make_password("Str0ng-password-123")

        self.assertTrue(encoded.startswith("argon2$argon2id$"))
        self.assertEqual(identify_hasher(encoded).algorithm, "argon2")

    def test_legacy_pbkdf2_passwords_still_verify(self):
        legacy = PBKDF2PasswordHasher().encode(
            "Str0ng-password-123",
            PBKDF2PasswordHasher().salt(),
        )

        self.assertTrue(legacy.startswith("pbkdf2_sha256$"))
        self.assertTrue(check_password("Str0ng-password-123", legacy))

    def test_legacy_hash_is_upgraded_on_next_sign_in(self):
        # This is the whole migration strategy: no data migration, no forced
        # password reset. The first successful sign-in rewrites the hash.
        user = User.objects.create_user(
            username="legacy@greenhillacademy.ac.ug",
            email="legacy@greenhillacademy.ac.ug",
            password="Str0ng-password-123",
        )
        User.objects.filter(pk=user.pk).update(
            password=PBKDF2PasswordHasher().encode(
                "Str0ng-password-123",
                PBKDF2PasswordHasher().salt(),
            )
        )
        user.refresh_from_db()
        self.assertTrue(user.password.startswith("pbkdf2_sha256$"))

        signed_in = authenticate(
            username="legacy@greenhillacademy.ac.ug",
            password="Str0ng-password-123",
        )

        self.assertIsNotNone(signed_in)
        user.refresh_from_db()
        self.assertTrue(user.password.startswith("argon2$argon2id$"))

    def test_memory_cost_stays_inside_a_small_instance(self):
        # 64 MiB per concurrent sign-in. Anything at Django's 100 MiB default
        # multiplied by a handful of simultaneous logins is a real out-of-memory
        # risk on a 512 MB container, so pin the intent.
        self.assertEqual(GreenHillArgon2PasswordHasher.memory_cost, 65536)
        self.assertEqual(GreenHillArgon2PasswordHasher.time_cost, 2)
        self.assertEqual(GreenHillArgon2PasswordHasher.parallelism, 1)

    def test_creating_a_user_stores_an_argon2_hash(self):
        user = User.objects.create_user(
            username="hash-check@greenhillacademy.ac.ug",
            email="hash-check@greenhillacademy.ac.ug",
            password="Str0ng-password-123",
        )
        user.refresh_from_db()

        self.assertTrue(user.password.startswith("argon2$argon2id$"))
        self.assertTrue(user.check_password("Str0ng-password-123"))
