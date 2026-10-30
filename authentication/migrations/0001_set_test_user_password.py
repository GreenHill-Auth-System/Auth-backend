"""Neutralised: this migration used to reset a user's password.

The original version read ``TEST_USER_PASSWORD`` from the environment and
overwrote the password of a hardcoded account. That is a credential backdoor:
anyone able to set an environment variable could take over that account on the
next ``migrate``.

The body is now a no-op. This is safe because ``RunPython`` contributes nothing
to migration state, so databases that already ran the old version are unaffected
and fresh databases no longer execute the dangerous code.

Use ``python manage.py createsuperuser`` or the Django admin to create accounts.
"""

from django.db import migrations


def noop(apps, schema_editor):
    """Intentionally empty. See the module docstring."""


class Migration(migrations.Migration):

    dependencies = []

    operations = [
        migrations.RunPython(noop, noop),
    ]