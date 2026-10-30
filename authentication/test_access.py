from django.test import TestCase

from .access import get_user_access
from .models import AllowedEmail


class GetUserAccessTests(TestCase):
    def test_listed_email_gets_its_role_and_systems(self):
        AllowedEmail.objects.create(
            email="boss@greenhillacademy.ac.ug",
            role=AllowedEmail.Role.MANAGER,
            authorized_systems=["EID", "Procurement"],
        )
        access = get_user_access("Boss@GreenhillAcademy.ac.ug")
        self.assertEqual(access["role"], "Manager")
        self.assertEqual(access["authorized_systems"], ["EID", "Procurement"])

    def test_unlisted_email_gets_no_systems(self):
        access = get_user_access("nobody@greenhillacademy.ac.ug")
        self.assertEqual(access["authorized_systems"], [])

    def test_inactive_entry_gets_no_systems(self):
        AllowedEmail.objects.create(
            email="gone@greenhillacademy.ac.ug",
            authorized_systems=["EID"],
            is_active=False,
        )
        access = get_user_access("gone@greenhillacademy.ac.ug")
        self.assertEqual(access["authorized_systems"], [])
