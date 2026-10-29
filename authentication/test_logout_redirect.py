from django.contrib.auth import get_user_model
from django.test import TestCase


class LogoutRedirectTests(TestCase):
    def test_logs_out_and_redirects(self):
        user = get_user_model().objects.create_user(
            username="a@greenhillacademy.ac.ug", password="x-long-pass-123"
        )
        self.client.force_login(user)

        response = self.client.get("/auth/logout-redirect/")

        self.assertEqual(response.status_code, 302)
        self.assertNotIn("_auth_user_id", self.client.session)