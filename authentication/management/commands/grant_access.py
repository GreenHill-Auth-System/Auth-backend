"""Grant, change or revoke a staff member's access, from the command line.

Roles and project access are keyed on the GreenHill email address, so this
command is the normal way to provision a person::

    python manage.py grant_access cnmusisi@greenhillacademy.ac.ug \
        --role CEO --systems eid,procurement,incident

    python manage.py grant_access jdoe@greenhillacademy.ac.ug \
        --role Staff --systems procurement

    python manage.py grant_access jdoe@greenhillacademy.ac.ug --revoke
    python manage.py grant_access --list

The address is validated against the same strict GreenHill pattern the sign-in
form uses, so a typo cannot quietly create an access row that will never match
a real login.
"""

from django.core.management.base import BaseCommand, CommandError

from authentication.domain_guard import (
    GREENHILL_EMAIL_EXAMPLE,
    is_valid_greenhill_email,
    normalize_email,
)
from authentication.models import AllowedEmail

# Friendly aliases, because nobody wants to type "Incident Service Management".
SYSTEM_ALIASES = {
    "eid": AllowedEmail.System.EID,
    "pms": AllowedEmail.System.PROCUREMENT,
    "procurement": AllowedEmail.System.PROCUREMENT,
    "ismp": AllowedEmail.System.INCIDENT,
    "incident": AllowedEmail.System.INCIDENT,
    "incident service management": AllowedEmail.System.INCIDENT,
}

ROLE_ALIASES = {
    "ceo": AllowedEmail.Role.CEO,
    "manager": AllowedEmail.Role.MANAGER,
    "staff": AllowedEmail.Role.STAFF,
}


def _parse_systems(raw_values):
    """Turn ``["eid,pms"]`` or ``[["eid", "pms"]]`` into canonical systems.

    ``--systems`` accepts three spellings, which all arrive here in different
    shapes::

        --systems eid,pms        -> ["eid,pms"]
        --systems eid pms        -> [["eid", "pms"]]
        --systems eid --systems pms -> ["eid", "pms"]

    Flattening first means the parsing below only ever deals with strings.
    """
    flat = []
    for raw in raw_values or []:
        if isinstance(raw, (list, tuple)):
            flat.extend(raw)
        else:
            flat.append(raw)

    resolved = []
    for raw in flat:
        for chunk in str(raw).replace(";", ",").split(","):
            key = chunk.strip().lower()
            if not key:
                continue
            system = SYSTEM_ALIASES.get(key)
            if system is None:
                raise CommandError(
                    f"Unknown system '{chunk.strip()}'. "
                    f"Choose from: {', '.join(sorted(SYSTEM_ALIASES))}."
                )
            if system not in resolved:
                resolved.append(system)
    return resolved


class Command(BaseCommand):
    help = (
        "Grant, update or revoke a GreenHill staff member's role and "
        "project access."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "email",
            nargs="?",
            help=(
                "GreenHill address, e.g. "
                f"{GREENHILL_EMAIL_EXAMPLE}. Omit when using --list."
            ),
        )
        parser.add_argument(
            "--role",
            choices=sorted(ROLE_ALIASES),
            help="Role to assign (defaults to Staff for a new row).",
        )
        parser.add_argument(
            "--systems",
            action="append",
            nargs="*",
            metavar="SYSTEM",
            help=(
                "Systems to grant: eid, procurement (pms), incident (ismp). "
                "Accepts 'eid,pms', 'eid pms' or a repeated flag. Pass the "
                "flag with no values to clear access."
            ),
        )
        parser.add_argument(
            "--revoke",
            action="store_true",
            help="Deactivate the row. Sign-in still works, but no project access is granted.",
        )
        parser.add_argument(
            "--activate",
            action="store_true",
            help="Reactivate a previously revoked row.",
        )
        parser.add_argument(
            "--list",
            action="store_true",
            help="List every provisioning row and exit.",
        )

    def handle(self, *args, **options):
        if options["list"]:
            self._list_rows()
            return

        raw_email = options.get("email")
        if not raw_email:
            raise CommandError(
                "An email address is required (or use --list)."
            )

        email = normalize_email(raw_email)
        if not is_valid_greenhill_email(email):
            raise CommandError(
                f"'{raw_email}' is not a valid GreenHill address. Expected "
                f"something like {GREENHILL_EMAIL_EXAMPLE}."
            )

        entry = AllowedEmail.objects.filter(email=email).first()

        if options["revoke"]:
            if entry is None:
                raise CommandError(f"No access row exists for {email}.")
            entry.is_active = False
            entry.save(update_fields=["is_active"])
            self.stdout.write(
                self.style.WARNING(f"{email}: access revoked.")
            )
            return

        if options["activate"]:
            if entry is None:
                raise CommandError(f"No access row exists for {email}.")
            entry.is_active = True
            entry.save(update_fields=["is_active"])
            self.stdout.write(self.style.SUCCESS(f"{email}: access restored."))
            return

        role = ROLE_ALIASES[options["role"]] if options["role"] else None
        systems = (
            _parse_systems(options["systems"])
            if options["systems"] is not None
            else None
        )

        if entry is None:
            if role is None:
                role = AllowedEmail.Role.STAFF
            if systems is None:
                systems = []

            entry = AllowedEmail.objects.create(
                email=email,
                role=role,
                authorized_systems=list(systems),
            )
            self.stdout.write(
                self.style.SUCCESS(
                    f"{email}: created with role {entry.role} and systems "
                    f"{entry.authorized_systems or 'none'}."
                )
            )
            return

        changed = []
        if role is not None and entry.role != role:
            entry.role = role
            changed.append("role")
        if systems is not None and list(entry.authorized_systems or []) != systems:
            entry.authorized_systems = list(systems)
            changed.append("authorized_systems")
        if not entry.is_active:
            entry.is_active = True
            changed.append("is_active")

        if not changed:
            self.stdout.write(
                f"{email}: already has role {entry.role} and systems "
                f"{entry.authorized_systems or 'none'}. Nothing to do."
            )
            return

        entry.save()
        self.stdout.write(
            self.style.SUCCESS(
                f"{email}: updated ({', '.join(changed)}). Role {entry.role}, "
                f"systems {entry.authorized_systems or 'none'}."
            )
        )

    def _list_rows(self):
        rows = AllowedEmail.objects.order_by("email")
        if not rows.exists():
            self.stdout.write("No provisioning rows yet.")
            return

        self.stdout.write(
            f"{'EMAIL':<48} {'ROLE':<9} {'ACTIVE':<7} SYSTEMS"
        )
        for row in rows:
            systems = ", ".join(row.authorized_systems or []) or "-"
            self.stdout.write(
                f"{row.email:<48} {row.role:<9} "
                f"{'yes' if row.is_active else 'no':<7} {systems}"
            )
