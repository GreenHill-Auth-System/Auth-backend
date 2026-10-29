from django.core.cache import cache
from django.test import TestCase


class LoginThrottleTests(TestCase):
    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    def test_login_is_rate_limited(self):
        statuses = []
        for _ in range(12):
            response = self.client.post(
                "/auth/login/",
                {"email": "nobody@greenhillacademy.ac.ug", "password": "wrong-pass"},
                content_type="application/json",
            )
            statuses.append(response.status_code)
        self.assertIn(429, statuses)
