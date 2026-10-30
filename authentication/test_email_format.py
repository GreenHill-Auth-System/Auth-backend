"""Tests for the strict GreenHill email policy.

The rule the schools asked for: every member of staff has an
``@greenhillacademy.ac.ug`` address whose local part is their name, so only
the name before the ``@`` ever changes. Those addresses are what roles get
assigned against, which means accepting a malformed one is a security
problem, not a cosmetic one.
"""

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from .domain_guard import (
    GREENHILL_EMAIL_EXAMPLE,
    GREENHILL_EMAIL_PATTERN,
    greenhill_local_part,
    is_greenhill_email,
    is_valid_greenhill_email,
    normalize_email,
    validate_greenhill_email,
)


class AcceptedAddressTests(SimpleTestCase):
    def test_sample_address_from_the_school(self):
        self.assertTrue(is_valid_greenhill_email("cnmusisi@greenhillacademy.ac.ug"))

    def test_short_named_address(self):
        self.assertTrue(is_valid_greenhill_email("refactory@greenhillacademy.ac.ug"))

    def test_single_letter_name(self):
        self.assertTrue(is_valid_greenhill_email("a@greenhillacademy.ac.ug"))

    def test_separators_between_name_parts(self):
        for address in (
            "cn.musisi@greenhillacademy.ac.ug",
            "cn-musisi@greenhillacademy.ac.ug",
            "cn_musisi@greenhillacademy.ac.ug",
            "cn.musisi.2@greenhillacademy.ac.ug",
        ):
            with self.subTest(address=address):
                self.assertTrue(is_valid_greenhill_email(address))

    def test_digits_after_the_first_letter(self):
        self.assertTrue(is_valid_greenhill_email("cnmusisi2@greenhillacademy.ac.ug"))

    def test_uppercase_and_padding_are_normalised_first(self):
        self.assertTrue(
            is_valid_greenhill_email("  CNMusisi@GreenHillAcademy.ac.ug  ")
        )

    def test_the_documented_example_is_itself_valid(self):
        self.assertTrue(is_valid_greenhill_email(GREENHILL_EMAIL_EXAMPLE))


class RejectedAddressTests(SimpleTestCase):
    def test_other_domains(self):
        for address in (
            "cnmusisi@gmail.com",
            "cnmusisi@greenhillacademy.com",
            "cnmusisi@greenhillacademy.ac.ug.com",
            "cnmusisi@sub.greenhillacademy.ac.ug",
            "cnmusisi@greenhillacademy.ac",
            "cnmusisi@notgreenhillacademy.ac.ug",
        ):
            with self.subTest(address=address):
                self.assertFalse(is_valid_greenhill_email(address))

    def test_plus_addressing(self):
        self.assertFalse(is_valid_greenhill_email("cnmusisi+test@greenhillacademy.ac.ug"))

    def test_empty_local_part(self):
        self.assertFalse(is_valid_greenhill_email("@greenhillacademy.ac.ug"))

    def test_leading_and_trailing_separators(self):
        for address in (
            ".cnmusisi@greenhillacademy.ac.ug",
            "cnmusisi.@greenhillacademy.ac.ug",
            "-cnmusisi@greenhillacademy.ac.ug",
            "_cnmusisi@greenhillacademy.ac.ug",
        ):
            with self.subTest(address=address):
                self.assertFalse(is_valid_greenhill_email(address))

    def test_doubled_separators(self):
        for address in (
            "cn..musisi@greenhillacademy.ac.ug",
            "cn--musisi@greenhillacademy.ac.ug",
            "cn._musisi@greenhillacademy.ac.ug",
        ):
            with self.subTest(address=address):
                self.assertFalse(is_valid_greenhill_email(address))

    def test_starts_with_a_digit(self):
        self.assertFalse(is_valid_greenhill_email("2cnmusisi@greenhillacademy.ac.ug"))

    def test_inner_whitespace(self):
        self.assertFalse(is_valid_greenhill_email("cn musisi@greenhillacademy.ac.ug"))

    def test_unicode_lookalikes(self):
        # Cyrillic "с" and a fullwidth "ｎ" must not slip through as ASCII.
        for address in (
            "сnmusisi@greenhillacademy.ac.ug",
            "cnmusisi@greenhillаcademy.ac.ug",
            "ｎcmusisi@greenhillacademy.ac.ug",
        ):
            with self.subTest(address=address):
                self.assertFalse(is_valid_greenhill_email(address))

    def test_blank_values(self):
        for address in ("", "   ", None):
            with self.subTest(address=address):
                self.assertFalse(is_valid_greenhill_email(address))


class DomainSuffixTests(SimpleTestCase):
    """``is_greenhill_email`` is the looser suffix check.

    The Google sign-in path uses it before the account exists, so it only has
    to answer "is this one of ours?" -- the strict format check runs after.
    """

    def test_accepts_our_domain(self):
        self.assertTrue(is_greenhill_email("cnmusisi@greenhillacademy.ac.ug"))

    def test_rejects_other_domains(self):
        self.assertFalse(is_greenhill_email("cnmusisi@gmail.com"))

    def test_blank_is_false(self):
        self.assertFalse(is_greenhill_email(""))
        self.assertFalse(is_greenhill_email(None))


class LocalPartTests(SimpleTestCase):
    def test_returns_the_name(self):
        self.assertEqual(
            greenhill_local_part("cnmusisi@greenhillacademy.ac.ug"),
            "cnmusisi",
        )

    def test_returns_empty_for_other_domains(self):
        self.assertEqual(greenhill_local_part("cnmusisi@gmail.com"), "")


class NormalizeTests(SimpleTestCase):
    def test_lowercases_and_strips(self):
        self.assertEqual(normalize_email("  CN@X.COM "), "cn@x.com")

    def test_none_and_blank_become_empty(self):
        self.assertEqual(normalize_email(None), "")
        self.assertEqual(normalize_email(""), "")


class ValidateTests(SimpleTestCase):
    def test_returns_the_normalised_address(self):
        self.assertEqual(
            validate_greenhill_email("  CNMusisi@GreenHillAcademy.ac.ug "),
            "cnmusisi@greenhillacademy.ac.ug",
        )

    def test_wrong_domain_error_code(self):
        with self.assertRaises(ValidationError) as caught:
            validate_greenhill_email("cnmusisi@gmail.com")
        self.assertEqual(caught.exception.code, "wrong_domain")

    def test_bad_format_error_code(self):
        with self.assertRaises(ValidationError) as caught:
            validate_greenhill_email("cn..musisi@greenhillacademy.ac.ug")
        self.assertEqual(caught.exception.code, "bad_format")

    def test_blank_error_code(self):
        with self.assertRaises(ValidationError) as caught:
            validate_greenhill_email("")
        self.assertEqual(caught.exception.code, "required")


class PatternTests(SimpleTestCase):
    def test_pattern_is_anchored(self):
        self.assertTrue(GREENHILL_EMAIL_PATTERN.startswith("^"))
        self.assertTrue(GREENHILL_EMAIL_PATTERN.endswith("$"))
