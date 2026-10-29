from django.test import TestCase

from .models import AllowedEmail


class AllowedEmailModelTests(TestCase):
    def test_email_is_lowercased_and_trimmed_on_save(self):
        entry = AllowedEmail.objects.create(email="  Jane@GreenHillAcademy.ac.ug ")
        self.assertEqual(entry.email, "jane@greenhillacademy.ac.ug")

    def test_defaults(self):
        entry = AllowedEmail.objects.create(email="staff@greenhillacademy.ac.ug")
        self.assertEqual(entry.role, AllowedEmail.Role.STAFF)
        self.assertEqual(entry.authorized_systems, [])
        self.assertTrue(entry.is_active)
