"""Create a sign-in account for a GreenHill staff member, with a password.

Two separate things make a person "in" to this system:

1. **A Django user** -- the row that holds the password and the
   ``is_staff`` / ``is_superuser`` flags. Those flags are what allow
   ``/admin/``, which is where roles are created and permissions assigned.
2. **An ``AllowedEmail`` row** -- the row that carries the role and the
   systems (EID / PMS / ISMP). Without it the person can sign in and sees an
   empty workspace picker.

``grant_access`` handles (2). ``createsuperuser`` handles half of (1) and
refuses to run non-interactively. This command does both in one step so the
two can never drift apart::

    python manage.py create_access_user tmugume@greenhillacademy.ac.ug \\
        --role CEO --systems eid procurement incident --name "T Mugume"

    python manage.py create_access_user jdoe@greenhillacademy.ac.ug \\
        --role Staff --systems procurement

The password is **generated**, printed exactly once, and never stored in the
repository, in a fixture, or in shell history. Pass ``--reset-password`` to
issue a new one for an existing account, and ``--password-from-stdin`` to type
your own without it appearing in the process list.
"""

import sys

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.utils.crypto import get_random_string

from authentication.domain_guard import (
    GREENHILL_EMAIL_EXAMPLE,
    is_valid_greenhill_email,
    normalize_email,
)
from authentication.models import AllowedEmail
from authentication.management.commands.grant_access import (
    ROLE_ALIASES,
    _parse_systems,
)

# Alphanumeric only, so the password survives being pasted into a shell, a
# URL, or a JSON body without quoting surprises. 24 characters is ~143 bits of
# entropy -- far beyond what the 10/minute login throttle could ever be brute
# forced against.
PASSWORD_LENGTH = 24


class Command(BaseCommand):
    help = (
        "Create (or update) a GreenHill account: Django user + role and "
        "system access, with a generated password."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "email",
            help=(
                "GreenHill address, e.g. "
                f"{GREENHILL_EMAIL_EXAMPLE}. Becomes both the email and "
                "the username."
            ),
        )
        # No `choices=` here on purpose: the model stores "CEO", "Manager"
        # and "Staff", so accepting only lowercase aliases would reject the
        # spelling the rest of the system uses. Normalised in handle().
        parser.add_argument(
            "--role",
            default="ceo",
            help=(
                "Role for the AllowedEmail row: CEO, Manager or Staff "
                "(case-insensitive). Defaults to CEO."
            ),
        )
        parser.add_argument(
            "--systems",
            action="append",
            nargs="*",
            metavar="SYSTEM",
            help=(
                "Systems to grant: eid, procurement (pms), incident (ismp). "
                "Accepts 'eid,pms', 'eid pms' or a repeated flag. Pass the "
                "flag with no values to grant none. Omit to grant all three."
            ),
        )
        parser.add_argument(
            "--name",
            default="",
            help='Full name, e.g. --name "T Mugume". Split on the first space.',
        )
        parser.add_argument(
            "--no-admin",
            action="store_true",
            help=(
                "Do not grant is_staff / is_superuser. The account can still "
                "sign in to the frontend, but cannot open /admin/."
            ),
        )
        parser.add_argument(
            "--reset-password",
            action="store_true",
            help="Issue a new password for an account that already exists.",
        )
        parser.add_argument(
            "--password-from-stdin",
            action="store_true",
            help=(
                "Read the password from the first line of stdin instead of "
                "generating one. Keeps it out of shell history."
            ),
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would change, write nothing.",
        )

    def handle(self, *args, **options):
        email = normalize_email(options["email"])

        if not is_valid_greenhill_email(email):
            raise CommandError(
                f"'{options['email']}' is not a valid GreenHill address. "
                f"Expected something like {GREENHILL_EMAIL_EXAMPLE}."
            )

        role = self._parse_role(options["role"])

        # Omitted --systems means "all three", which is the sensible default
        # for the people who administer the system. An explicit empty flag
        # means "none".
        #
        # `_parse_systems` returns TextChoices members; unwrap them to plain
        # strings so what gets written to the JSON column is identical however
        # the list was built.
        if options["systems"] is None:
            systems = list(AllowedEmail.System.values)
        else:
            systems = _parse_systems(options["systems"])
        systems = [str(system) for system in systems]

        if options["dry_run"]:
            self._report(email, role, systems, options)
            return

        user, user_created = self._upsert_user(email, options)
        entry, entry_created = self._upsert_access(email, role, systems)

        password = None
        if user_created or options["reset_password"]:
            password = self._set_password(user, options)

        self._print_summary(
            user=user,
            created=user_created,
            entry=entry,
            entry_created=entry_created,
            password=password,
        )

    # -- steps ----------------------------------------------------------

    def _parse_role(self, raw):
        """Accept ``CEO``, ``ceo``, ``Manager``, ``manager`` ...

        The model's values are capitalised but the CLI aliases are not, so a
        plain ``ROLE_ALIASES[raw]`` lookup would reject the obvious spelling.
        """
        key = str(raw or "").strip().lower()
        role = ROLE_ALIASES.get(key)
        if role is None:
            raise CommandError(
                f"Unknown role '{raw}'. Choose from: "
                f"{', '.join(sorted(ROLE_ALIASES))}."
            )
        return role

    def _upsert_user(self, email, options):
        User = get_user_model()

        user = User.objects.filter(email__iexact=email).order_by("pk").first()
        created = user is None

        if created:
            # A row may already hold this address as its *username* with a
            # blank or stale email -- typically a createsuperuser run from
            # before the unique-email index existed. That is the same person,
            # so adopt the row and repair the email instead of refusing.
            clash = (
                User.objects.filter(username__iexact=email).order_by("pk").first()
            )
            if clash is None:
                user = User(username=email, email=email)
            elif clash.email and clash.email.lower() != email.lower():
                # Two accounts sharing an identifier is a real problem, so
                # this is an error rather than a silent rename.
                raise CommandError(
                    f"A user with username '{email}' already exists but has a "
                    f"different email ({clash.email}). Resolve it before "
                    "retrying."
                )
            else:
                # Adopted, not created: the account already exists, so its
                # password is left untouched (use --reset-password to issue a
                # new one).
                user = clash
                created = False

        first, _, last = options["name"].partition(" ")
        if options["name"]:
            user.first_name = first.strip()
            user.last_name = last.strip()

        user.is_active = True
        if not options["no_admin"]:
            user.is_staff = True
            user.is_superuser = True

        # An existing account may predate the unique-email index, or have been
        # created by createsuperuser with a blank email. Repair it here.
        if not user.email:
            user.email = email

        user.save()
        return user, created

    def _upsert_access(self, email, role, systems):
        entry = AllowedEmail.objects.filter(email=email).first()
        created = entry is None

        if created:
            entry = AllowedEmail(
                email=email,
                role=role,
                authorized_systems=list(systems),
            )
        else:
            entry.role = role
            entry.authorized_systems = list(systems)
            entry.is_active = True

        entry.save()
        return entry, created

    def _set_password(self, user, options):
        if options["password_from_stdin"]:
            password = (sys.stdin.readline() or "").strip()
            if not password:
                raise CommandError("No password supplied on stdin.")
        else:
            password = get_random_string(PASSWORD_LENGTH)

        try:
            validate_password(password, user=user)
        except ValidationError as exc:
            raise CommandError(
                "That password is rejected by the configured validators: "
                + "; ".join(exc.messages)
            ) from exc

        user.set_password(password)
        user.save(update_fields=["password"])
        return password

    # -- output ---------------------------------------------------------

    def _report(self, email, role, systems, options):
        self.stdout.write(
            f"[dry run] would create account {email}\n"
            f"          role    {role}\n"
            f"          systems {systems or 'none'}\n"
            f"          admin   {not options['no_admin']}"
        )

    def _print_summary(self, *, user, created, entry, entry_created, password):
        verb = "created" if created else "updated"
        self.stdout.write(
            self.style.SUCCESS(f"{user.email}: account {verb}.")
        )
        self.stdout.write(
            f"  username        {user.username}\n"
            f"  role            {entry.role}"
            f"{' (new row)' if entry_created else ''}\n"
            f"  systems         {entry.authorized_systems or 'none'}\n"
            f"  admin access    "
            f"{'yes' if user.is_superuser else 'no'}"
        )

        if password is None:
            self.stdout.write(
                self.style.WARNING(
                    "  password        unchanged (pass --reset-password to "
                    "issue a new one)"
                )
            )
            return

        self.stdout.write("")
        self.stdout.write(
            self.style.WARNING(
                "  This password is shown ONCE. It is not stored anywhere "
                "recoverable."
            )
        )
        self.stdout.write(self.style.MIGRATE_HEADING(f"  PASSWORD: {password}"))
        self.stdout.write(
            "  Give it to the person over a channel you trust, then have "
            "them change it."
        )
