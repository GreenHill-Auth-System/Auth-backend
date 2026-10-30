"""Tests for relying-party registration and the grant_access command.

``seed_oauth_clients`` is what turns three environment variables into three
working OIDC clients, so it is exercised against the real ``Application``
model. ``grant_access`` is how an address gets a role in the first place.
"""

import os
from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from oauth2_provider.models import get_application_model

from .clients import RELYING_PARTIES, get_relying_party
from .models import AllowedEmail

Application = get_application_model()

EID = get_relying_party("eid")
PROCUREMENT = get_relying_party("procurement")
INCIDENT = get_relying_party("incident")


def env_for(party, uris, logout=(), origins=()):
    return {
        party.redirect_uris_env: uris,
        party.post_logout_redirect_uris_env: " ".join(logout),
        party.allowed_origins_env: " ".join(origins),
    }


class RelyingPartyDefinitionTests(TestCase):
    def test_three_systems_are_defined(self):
        self.assertEqual(len(RELYING_PARTIES), 3)
        self.assertEqual(
            [party.system for party in RELYING_PARTIES],
            ["EID", "Procurement", "Incident Service Management"],
        )

    def test_scopes_match_the_provider_configuration(self):
        self.assertEqual(EID.scope, "eid")
        self.assertEqual(PROCUREMENT.scope, "procurement")
        self.assertEqual(INCIDENT.scope, "incident")

    def test_allowed_scopes_include_the_base_scopes(self):
        for party in RELYING_PARTIES:
            with self.subTest(party=party.key):
                self.assertIn("openid", party.allowed_scopes)
                self.assertIn(party.scope, party.allowed_scopes)

    def test_unknown_key_returns_none(self):
        self.assertIsNone(get_relying_party("nope"))


class SeedClientCommandTests(TestCase):
    def _run(self, env, *args):
        out = StringIO()
        with mock.patch.dict(os.environ, env, clear=False):
            call_command("seed_oauth_clients", *args, stdout=out)
        return out.getvalue()

    def test_creates_a_confidential_authorization_code_client(self):
        self._run(
            env_for(
                EID,
                "https://eid.example/callback",
                logout=["https://eid.example/signed-out"],
                origins=["https://eid.example"],
            )
        )

        application = Application.objects.get(name=EID.name)
        self.assertEqual(application.client_type, "confidential")
        self.assertEqual(application.authorization_grant_type, "authorization-code")
        self.assertTrue(application.skip_authorization)
        self.assertEqual(
            application.redirect_uris.split(),
            ["https://eid.example/callback"],
        )
        self.assertEqual(
            application.post_logout_redirect_uris.split(),
            ["https://eid.example/signed-out"],
        )

    def test_is_idempotent(self):
        env = env_for(EID, "https://eid.example/callback")
        self._run(env)
        self._run(env)
        self.assertEqual(Application.objects.filter(name=EID.name).count(), 1)

    def test_prints_a_generated_secret_once(self):
        output = self._run(env_for(EID, "https://eid.example/callback"))
        self.assertIn("client secret", output.lower())
        self.assertEqual(Application.objects.filter(name=EID.name).count(), 1)

    def test_dry_run_writes_nothing(self):
        output = self._run(
            env_for(EID, "https://eid.example/callback"),
            "--dry-run",
        )
        self.assertIn("would create", output)
        self.assertEqual(Application.objects.count(), 0)

    def test_unconfigured_party_is_skipped_with_a_warning(self):
        # A developer's real .env supplies redirect URIs for all three parties,
        # so blank the other two explicitly instead of relying on them being
        # absent from the environment.
        with mock.patch.dict(
            os.environ,
            {
                PROCUREMENT.redirect_uris_env: "",
                INCIDENT.redirect_uris_env: "",
            },
            clear=False,
        ):
            output = self._run({EID.redirect_uris_env: "https://eid.example/callback"})
        self.assertIn("skipped", output)
        self.assertEqual(Application.objects.filter(name=PROCUREMENT.name).count(), 0)

    def test_raises_when_nothing_is_configured(self):
        with mock.patch.dict(
            os.environ,
            {
                EID.redirect_uris_env: "",
                PROCUREMENT.redirect_uris_env: "",
                INCIDENT.redirect_uris_env: "",
            },
            clear=False,
        ):
            with self.assertRaises(CommandError):
                call_command("seed_oauth_clients", stdout=StringIO())

    def test_separates_multiple_uris_on_commas_or_spaces(self):
        self._run(
            env_for(
                EID,
                "https://eid.example/callback, https://eid.example/alt",
            )
        )
        application = Application.objects.get(name=EID.name)
        self.assertEqual(len(application.redirect_uris.split()), 2)

    def test_rotation_replaces_the_secret(self):
        self._run(env_for(EID, "https://eid.example/callback"))
        before = Application.objects.get(name=EID.name).client_secret

        self._run(env_for(EID, "https://eid.example/callback"), "--rotate-secrets")

        after = Application.objects.get(name=EID.name).client_secret
        self.assertNotEqual(before, after)


class GrantAccessCommandTests(TestCase):
    def test_grants_a_role_and_systems(self):
        call_command(
            "grant_access",
            "cnmusisi@greenhillacademy.ac.ug",
            "--role", "manager",
            "--systems", "eid", "pms",
            stdout=StringIO(),
        )

        entry = AllowedEmail.objects.get(email="cnmusisi@greenhillacademy.ac.ug")
        self.assertEqual(entry.role, AllowedEmail.Role.MANAGER)
        self.assertEqual(
            sorted(entry.authorized_systems),
            sorted([AllowedEmail.System.EID, AllowedEmail.System.PROCUREMENT]),
        )
        self.assertTrue(entry.is_active)

    def test_normalises_the_address(self):
        call_command(
            "grant_access",
            "  CNMusisi@GreenHillAcademy.ac.ug ",
            stdout=StringIO(),
        )
        self.assertTrue(
            AllowedEmail.objects.filter(
                email="cnmusisi@greenhillacademy.ac.ug"
            ).exists()
        )

    def test_rejects_a_foreign_domain(self):
        with self.assertRaises(CommandError):
            call_command("grant_access", "cnmusisi@gmail.com", stdout=StringIO())

    def test_rejects_a_malformed_address(self):
        with self.assertRaises(CommandError):
            call_command(
                "grant_access",
                "cn..musisi@greenhillacademy.ac.ug",
                stdout=StringIO(),
            )

    def test_incident_alias_resolves_to_the_full_system_name(self):
        call_command(
            "grant_access",
            "cnmusisi@greenhillacademy.ac.ug",
            "--systems", "ismp",
            stdout=StringIO(),
        )
        entry = AllowedEmail.objects.get(email="cnmusisi@greenhillacademy.ac.ug")
        self.assertIn(
            AllowedEmail.System.INCIDENT,
            entry.authorized_systems,
        )

    def test_revoke_deactivates_without_deleting(self):
        call_command(
            "grant_access",
            "cnmusisi@greenhillacademy.ac.ug",
            stdout=StringIO(),
        )
        call_command(
            "grant_access",
            "cnmusisi@greenhillacademy.ac.ug",
            "--revoke",
            stdout=StringIO(),
        )

        entry = AllowedEmail.objects.get(email="cnmusisi@greenhillacademy.ac.ug")
        self.assertFalse(entry.is_active)

    def test_list_prints_a_table(self):
        call_command(
            "grant_access",
            "cnmusisi@greenhillacademy.ac.ug",
            "--systems", "eid",
            stdout=StringIO(),
        )
        output = StringIO()
        call_command("grant_access", "--list", stdout=output)
        self.assertIn("cnmusisi@greenhillacademy.ac.ug", output.getvalue())
