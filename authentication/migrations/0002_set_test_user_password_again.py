"""Neutralised: duplicate of 0001, which reset a user's password from an env var.

See ``0001_set_test_user_password`` for the rationale. The body is now a no-op;
``RunPython`` does not affect migration state, so this is safe for databases that
already applied the original.
"""

from django.db import migrations


def noop(apps, schema_editor):
    """Intentionally empty. See the module docstring."""


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0001_set_test_user_password"),
    ]

    operations = [
        migrations.RunPython(noop, noop),
    ]