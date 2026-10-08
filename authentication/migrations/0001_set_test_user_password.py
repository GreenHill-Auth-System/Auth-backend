from django.db import migrations
from django.contrib.auth.hashers import make_password
import os


def set_test_user_password(apps, schema_editor):
    User = apps.get_model("auth", "User")

    email = "refactory@greenhillacademy.ac.ug"
    password = os.getenv("TEST_USER_PASSWORD")

    if not password:
        return

    User.objects.filter(email=email).update(
        password=make_password(password)
    )


def reverse_test_user_password(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = []

    operations = [
        migrations.RunPython(
            set_test_user_password,
            reverse_test_user_password,
        ),
    ]