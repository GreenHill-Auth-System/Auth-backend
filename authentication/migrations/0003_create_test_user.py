from django.db import migrations
from django.contrib.auth.hashers import make_password
import os


def create_test_user(apps, schema_editor):
    User = apps.get_model("auth", "User")

    email = "refactory@greenhillacademy.ac.ug"
    password = os.getenv("TEST_USER_PASSWORD")

    if not password:
        return

    user, created = User.objects.get_or_create(
        email=email,
        defaults={
            "username": email,
            "is_active": True,
        },
    )

    user.username = email
    user.password = make_password(password)
    user.is_active = True
    user.save()


def reverse_create_test_user(apps, schema_editor):
    User = apps.get_model("auth", "User")

    User.objects.filter(
        email="refactory@greenhillacademy.ac.ug"
    ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0002_set_test_user_password_again"),
    ]

    operations = [
        migrations.RunPython(
            create_test_user,
            reverse_create_test_user,
        ),
    ]