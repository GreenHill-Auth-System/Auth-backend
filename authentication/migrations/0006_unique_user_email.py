"""Make ``auth.User.email`` unique, case-insensitively.

Django ships ``email`` as a non-unique ``EmailField``. For an SSO identity
provider the email address *is* the identity, so two rows sharing an address
would let one person sign in as another.

A plain ``unique=True`` constraint is not possible without a custom user model
(and therefore a database reset), so instead this migration creates a functional
partial unique index directly on the ``auth_user`` table:

* ``LOWER(email)`` makes ``Alice@x`` and ``alice@x`` the same identity.
* ``WHERE email <> ''`` allows the many blank-email rows Django permits
  (staff-only accounts, imported data) while still rejecting real duplicates.

The pre-check runs first and fails loudly with the offending addresses instead
of letting the index creation produce an opaque ``IntegrityError``.
"""

from django.db import migrations
from django.db.models import Count
from django.db.models.functions import Lower

INDEX_NAME = "auth_user_email_lower_uniq"

CREATE_INDEX_SQL = f"""
CREATE UNIQUE INDEX {INDEX_NAME}
ON auth_user (LOWER(email))
WHERE email <> '' AND email IS NOT NULL;
"""

DROP_INDEX_SQL = f"DROP INDEX IF EXISTS {INDEX_NAME};"


def ensure_unique_lower_email(apps, schema_editor):
    """Abort with a readable report if duplicate addresses exist."""
    User = apps.get_model("auth", "User")
    db_alias = schema_editor.connection.alias

    duplicates = (
        User.objects.using(db_alias)
        .exclude(email__isnull=True)
        .exclude(email="")
        .annotate(email_lower=Lower("email"))
        .values("email_lower")
        .annotate(total=Count("pk"))
        .filter(total__gt=1)
        .order_by("-total", "email_lower")
    )

    report = [f"  {row['email_lower']} (x{row['total']})" for row in duplicates]

    if not report:
        return

    raise RuntimeError(
        "Cannot create the unique email index: auth_user already contains "
        "duplicate addresses:\n\n"
        + "\n".join(report)
        + "\n\nResolve them first — keep the lowest pk if it is the original "
        "account, then re-run `python manage.py migrate`."
    )


def noop(apps, schema_editor):
    """Nothing to undo: the pre-check changes no data."""


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0005_googleidentity"),
        # The index targets a table owned by django.contrib.auth, so it must
        # exist before this runs.
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.RunPython(ensure_unique_lower_email, noop),
        migrations.RunSQL(
            sql=CREATE_INDEX_SQL,
            reverse_sql=DROP_INDEX_SQL,
        ),
    ]
