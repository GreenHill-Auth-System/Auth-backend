"""Tests for the create_access_user command.

The command creates two things that must stay in step: a Django user (which
holds the password and the /admin/ flags) and an ``AllowedEmail`` row (which
holds the role and the systems). These tests pin both, plus the rule that a
password is only ever issued once unless explicitly asked for.
"""

import re
from io import StringIO
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from .models import AllowedEmail

User = get_user_model()

EMAIL = "cnmusisi@greenhillacademy.ac.ug"
OTHER = "jdoe@greenhillacademy.ac.ug"
OFF_DOMAIN = "cnmusisi@example.com"

ALL_SYSTEMS = [
    AllowedEmail.System.EID,
    AllowedEmail.System.PROCUREMENT,
    AllowedEmail.System.INCIDENT,
]

# The command prints "  PASSWORD: <value>" on a single line. Under the test
# runner the line is wrapped in ANSI colour codes, so strip those first --
# otherwise the captured "password" ends in an escape sequence and
# check_password() gets a string nobody ever had.
ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")
PASSWORD_PATTERN = re.compile(r"PASSWORD:\s*(\S+)")


def plain(output):
    """Test output with ANSI colour codes removed."""
    return ANSI_PATTERN.sub("", output)


class CreateAccessUserTests(TestCase):
    def _run(self, email=EMAIL, *args):
        out = StringIO()
        call_command("create_access_user", email, *args, stdout=out)
        return out.getvalue()

    def _password_from(self, output):
        match = PASSWORD_PATTERN.search(plain(output))
        self.assertIsNotNone(match, f"no password printed in:\n{output}")
        return match.group(1)

    # -- the happy path ---------------------------------------------------

    def test_creates_a_superuser_with_the_email_as_username(self):
        self._run()

        user = User.objects.get(email=EMAIL)
        self.assertEqual(user.username, EMAIL)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_active)

    def test_creates_the_matching_access_row(self):
        self._run()

        entry = AllowedEmail.objects.get(email=EMAIL)
        self.assertEqual(entry.role, AllowedEmail.Role.CEO)
        self.assertEqual(entry.authorized_systems, list(AllowedEmail.System.values))
        self.assertTrue(entry.is_active)

    def test_the_stored_password_actually_authenticates(self):
        password = self._password_from(self._run())

        user = User.objects.get(email=EMAIL)
        self.assertTrue(user.check_password(password))

    def test_the_printed_password_is_long_and_not_the_email(self):
        password = self._password_from(self._run())

        self.assertGreaterEqual(len(password), 20)
        self.assertNotIn("cnmusisi", password.lower())

    # -- role and system options -----------------------------------------

    def test_role_accepts_the_capitalised_spelling(self):
        self._run(EMAIL, "--role", "Staff")

        self.assertEqual(AllowedEmail.objects.get(email=EMAIL).role, "Staff")

    def test_role_accepts_lower_case(self):
        self._run(EMAIL, "--role", "manager")

        self.assertEqual(AllowedEmail.objects.get(email=EMAIL).role, "Manager")

    def test_unknown_role_is_rejected(self):
        with self.assertRaises(CommandError):
            self._run(EMAIL, "--role", "Wizard")

    def test_systems_accept_a_comma_separated_list(self):
        self._run(EMAIL, "--systems", "eid,pms")

        self.assertEqual(
            AllowedEmail.objects.get(email=EMAIL).authorized_systems,
            ["EID", "Procurement"],
        )

    def test_unknown_system_is_rejected(self):
        with self.assertRaises(CommandError):
            self._run(EMAIL, "--systems", "payroll")

    def test_empty_systems_flag_grants_nothing(self):
        self._run(EMAIL, "--systems")

        self.assertEqual(
            AllowedEmail.objects.get(email=EMAIL).authorized_systems,
            [],
        )

    # -- account flags ----------------------------------------------------

    def test_no_admin_still_creates_a_working_account(self):
        self._run(EMAIL, "--no-admin")

        user = User.objects.get(email=EMAIL)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertTrue(AllowedEmail.objects.filter(email=EMAIL).exists())

    def test_name_is_split_across_first_and_last(self):
        self._run(EMAIL, "--name", "T Mugume")

        user = User.objects.get(email=EMAIL)
        self.assertEqual(user.first_name, "T")
        self.assertEqual(user.last_name, "Mugume")

    # -- validation -------------------------------------------------------

    def test_off_domain_address_is_rejected(self):
        with self.assertRaises(CommandError):
            self._run(OFF_DOMAIN)
        self.assertEqual(User.objects.filter(email=OFF_DOMAIN).count(), 0)

    def test_malformed_local_part_is_rejected(self):
        with self.assertRaises(CommandError):
            self._run("cn.musisi+x@greenhillacademy.ac.ug")

    # -- idempotency ------------------------------------------------------

    def test_running_twice_does_not_duplicate_anything(self):
        self._run()
        self._run()

        self.assertEqual(User.objects.filter(email=EMAIL).count(), 1)
        self.assertEqual(AllowedEmail.objects.filter(email=EMAIL).count(), 1)

    def test_second_run_leaves_the_password_alone(self):
        first = self._password_from(self._run())
        second_output = self._run()

        self.assertIn("password        unchanged", plain(second_output))
        self.assertIsNone(PASSWORD_PATTERN.search(plain(second_output)))
        self.assertTrue(User.objects.get(email=EMAIL).check_password(first))

    def test_reset_password_issues_a_new_working_password(self):
        first = self._password_from(self._run())
        second = self._password_from(self._run(EMAIL, "--reset-password"))

        self.assertNotEqual(first, second)
        self.assertTrue(User.objects.get(email=EMAIL).check_password(second))

    def test_case_differences_match_the_existing_account(self):
        self._run()
        self._run(EMAIL.upper())

        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(AllowedEmail.objects.count(), 1)

    # -- password from stdin ----------------------------------------------

    def test_password_can_be_supplied_on_stdin(self):
        with mock.patch("sys.stdin", StringIO("Str0ng-Passphrase-Here\n")):
            self._run(EMAIL, "--password-from-stdin")

        self.assertTrue(
            User.objects.get(email=EMAIL).check_password("Str0ng-Passphrase-Here")
        )

    def test_weak_stdin_password_is_rejected(self):
        with mock.patch("sys.stdin", StringIO("12345678\n")):
            with self.assertRaises(CommandError):
                self._run(EMAIL, "--password-from-stdin")

    def test_empty_stdin_password_is_rejected(self):
        with mock.patch("sys.stdin", StringIO("\n")):
            with self.assertRaises(CommandError):
                self._run(EMAIL, "--password-from-stdin")

    # -- dry run ----------------------------------------------------------

    def test_dry_run_writes_nothing(self):
        output = self._run(EMAIL, "--dry-run")

        self.assertIn("dry run", plain(output))
        self.assertEqual(User.objects.count(), 0)
        self.assertEqual(AllowedEmail.objects.count(), 0)
        self.assertIsNone(PASSWORD_PATTERN.search(plain(output)))

    # -- repairing existing accounts --------------------------------------

    def test_existing_user_with_blank_email_is_repaired(self):
        User.objects.create_user(username=EMAIL, email="", password="secret123")

        self._run(EMAIL)

        # A blank-email row cannot be matched by find_user_by_email, so the
        # command must fill the email in rather than silently sign the person
        # out of their own account.
        self.assertEqual(User.objects.filter(email=EMAIL).count(), 1)

    def test_repairing_a_blank_email_account_keeps_its_password(self):
        User.objects.create_user(username=EMAIL, email="", password="secret123")

        output = self._run(EMAIL)

        # The account already existed, so its password must survive: adopting
        # a row is not the same as creating one.
        self.assertTrue(User.objects.get(email=EMAIL).check_password("secret123"))
        self.assertIn("password        unchanged", plain(output))

    def test_username_clash_on_a_different_email_is_an_error(self):
        User.objects.create_user(
            username=OTHER,
            email="somebody-else@greenhillacademy.ac.ug",
            password="secret123",
        )

        with self.assertRaises(CommandError):
            self._run(OTHER)
