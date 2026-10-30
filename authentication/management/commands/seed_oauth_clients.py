"""Create or update the three first-party OAuth 2.0 clients.

Run this after every deployment, and whenever a redirect URI changes::

    python manage.py seed_oauth_clients

It is idempotent -- clients are matched on their name, so running it twice does
not create duplicates.

Configuration comes from the environment:

===========================  ============================================
``<PREFIX>_REDIRECT_URIS``   space/comma separated ``https://app/callback``
``<PREFIX>_POST_LOGOUT_...`` space/comma separated post-logout targets
``<PREFIX>_ALLOWED_ORIGINS`` space/comma separated browser origins (CORS)
``<PREFIX>_CLIENT_ID``       optional; generated when absent
``<PREFIX>_CLIENT_SECRET``   optional; generated when absent
===========================  ============================================

``<PREFIX>`` is ``EID``, ``PROCUREMENT`` or ``INCIDENT``.

Secrets are printed once, when they are generated. Store them in the internal
secrets manager and in each system's environment (``OIDC_CLIENT_SECRET``).
Django OAuth Toolkit stores only a hash of a client secret, so a lost secret
cannot be recovered -- rerun with ``--rotate-secrets`` instead.

Note that each redirect URI must match exactly: a trailing slash is
significant, and no wildcards are allowed (RFC 9700 requires exact matching).
"""

from django.core.management.base import BaseCommand, CommandError
from oauth2_provider.models import Application
from oauth2_provider.generators import generate_client_secret

from authentication.clients import (
    RELYING_PARTIES,
    allowed_origins,
    declared_client_id,
    declared_client_secret,
    post_logout_redirect_uris,
    redirect_uris,
)

CONFIDENTIAL = "confidential"
AUTHORIZATION_CODE = "authorization-code"


class Command(BaseCommand):
    help = "Create or update the OAuth 2.0 clients for EID, Procurement and Incident."

    def add_arguments(self, parser):
        parser.add_argument(
            "--rotate-secrets",
            action="store_true",
            help=(
                "Generate a new client secret for each client even when "
                "nothing else changed. The old secret stops working "
                "immediately."
            ),
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would change without writing anything.",
        )

    def handle(self, *args, **options):
        rotate = options["rotate_secrets"]
        dry_run = options["dry_run"]

        created_count = 0
        updated_count = 0
        secrets = []

        for relying_party in RELYING_PARTIES:
            uris = redirect_uris(relying_party)
            if not uris:
                self.stdout.write(
                    self.style.WARNING(
                        f"{relying_party.name}: skipped, "
                        f"{relying_party.redirect_uris_env} is not set. "
                        "Set it to the callback URL of the system, e.g. "
                        "https://eid.example.com/callback"
                    )
                )
                continue

            existing = Application.objects.filter(
                name=relying_party.name
            ).first()

            client_id = declared_client_id(relying_party)
            client_secret = declared_client_secret(relying_party)

            should_set_secret = False
            if existing is None:
                should_set_secret = True
            elif rotate or client_secret:
                should_set_secret = True

            if existing is None and not client_secret:
                client_secret = generate_client_secret()
                should_set_secret = True
                secrets.append((relying_party.name, client_secret))

            if rotate and not declared_client_secret(relying_party):
                client_secret = generate_client_secret()
                should_set_secret = True
                secrets.append((relying_party.name, client_secret))

            fields = {
                "redirect_uris": " ".join(uris),
                "post_logout_redirect_uris": " ".join(
                    post_logout_redirect_uris(relying_party)
                ),
                "allowed_origins": " ".join(allowed_origins(relying_party)),
                "client_type": CONFIDENTIAL,
                "authorization_grant_type": AUTHORIZATION_CODE,
                # First-party: no consent screen. The authorisation endpoint
                # still enforces per-user scopes.
                "skip_authorization": True,
            }

            if client_id and existing is None:
                fields["client_id"] = client_id
            if should_set_secret:
                fields["client_secret"] = client_secret

            if dry_run:
                action = "would create" if existing is None else "would update"
                self.stdout.write(
                    f"{relying_party.name}: {action} "
                    f"(scopes: {' '.join(relying_party.allowed_scopes)})"
                )
                continue

            if existing is None:
                Application.objects.create(name=relying_party.name, **fields)
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f"{relying_party.name}: created")
                )
            else:
                for attribute, value in fields.items():
                    setattr(existing, attribute, value)
                existing.save()
                updated_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f"{relying_party.name}: updated")
                )

        if dry_run:
            self.stdout.write(self.style.NOTICE("Dry run: nothing was written."))
            return

        self.stdout.write("")
        self.stdout.write("Registered clients:")
        for application in Application.objects.order_by("name"):
            self.stdout.write(
                f"  {application.name:<40} client_id={application.client_id}"
            )

        if secrets:
            self.stdout.write("")
            self.stdout.write(
                self.style.WARNING(
                    "Newly generated client secrets -- copy them now, they are "
                    "stored hashed and cannot be shown again:"
                )
            )
            for name, secret in secrets:
                self.stdout.write(f"  {name}: {secret}")

        if created_count + updated_count == 0:
            raise CommandError(
                "No clients were configured. Set at least "
                "EID_REDIRECT_URIS, PROCUREMENT_REDIRECT_URIS and "
                "INCIDENT_REDIRECT_URIS."
            )

        self.stdout.write("")
        self.stdout.write(
            self.style.SUCCESS(
                f"Done: {created_count} created, {updated_count} updated."
            )
        )
