"""Neutralised: this migration created a user from an environment variable.

The original version read ``TEST_USER_PASSWORD`` and created or overwrote the
hardcoded account ``refactory@greenhillacademy.ac.ug``. Besides being a
credential backdoor, it made the schema history depend on an environment
variable — a fresh ``migrate`` in production with that variable set would reset
the CEO's password.

The body is now a no-op. ``RunPython`` contributes nothing to migration state,
so this is safe for databases that already applied the original.

Use ``python manage.py createsuperuser`` or the Django admin to create accounts.
"""

from django.db import migrations


def noop(apps, schema_editor):
    """Intentionally empty. See the module docstring."""


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0002_set_test_user_password_again"),
    ]

    operations = [
        migrations.RunPython(noop, noop),
    ]