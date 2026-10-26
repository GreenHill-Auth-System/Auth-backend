import os

from django.conf import settings
from django.contrib.auth import get_user_model, password_validation
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from authentication.local_test_user import LOCAL_TEST_USER_EMAIL


class Command(BaseCommand):
    help = "Create or reset the non-admin local development test user."

    def handle(self, *args, **options):
        if not settings.DEBUG:
            raise CommandError(
                "The local test user can only be created when DEBUG=True."
            )

        password = os.getenv("LOCAL_TEST_USER_PASSWORD")
        if not password:
            raise CommandError(
                "Set LOCAL_TEST_USER_PASSWORD before running this command."
            )

        User = get_user_model()
        user, _ = User.objects.get_or_create(
            username=LOCAL_TEST_USER_EMAIL,
            defaults={
                "email": LOCAL_TEST_USER_EMAIL,
                "is_active": True,
            },
        )

        try:
            password_validation.validate_password(password, user)
        except ValidationError as error:
            raise CommandError("; ".join(error.messages)) from error

        user.email = LOCAL_TEST_USER_EMAIL
        user.is_active = True
        user.is_staff = False
        user.is_superuser = False
        user.set_password(password)
        user.save()

        self.stdout.write(
            self.style.SUCCESS(
                f"Local test user is ready: {LOCAL_TEST_USER_EMAIL}"
            )
        )
