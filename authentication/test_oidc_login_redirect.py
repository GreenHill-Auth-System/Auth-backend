from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings

from authentication.views import get_oidc_authorize_return_to


@override_settings(
    OAUTH2_PROVIDER={
        "OIDC_ISS_ENDPOINT": "https://greenhill-auth-backend2.onrender.com/o",
    }
)
class OIDCLoginRedirectTests(SimpleTestCase):
    def test_accepts_the_provider_authorization_endpoint(self):
        target = (
            "https://greenhill-auth-backend2.onrender.com/o/authorize/"
            "?client_id=ismp-client&response_type=code"
        )

        self.assertEqual(get_oidc_authorize_return_to(target), target)

    def test_rejects_redirects_to_other_hosts(self):
        target = "https://attacker.example/o/authorize/?client_id=ismp"

        self.assertIsNone(get_oidc_authorize_return_to(target))

    def test_rejects_non_authorization_paths(self):
        target = "https://greenhill-auth-backend2.onrender.com/o/logout/?next=/"

        self.assertIsNone(get_oidc_authorize_return_to(target))

    def test_rejects_authorization_urls_with_fragments(self):
        target = (
            "https://greenhill-auth-backend2.onrender.com/o/authorize/"
            "?client_id=ismp#fragment"
        )

        self.assertIsNone(get_oidc_authorize_return_to(target))


@override_settings(FRONTEND_URL="https://greenhill-auth-frontend2.onrender.com")
class OIDCLogoutRedirectTests(TestCase):
    def test_logout_returns_user_to_auth_login(self):
        user = get_user_model().objects.create_user(
            username="user@example.test",
            password="test-password",
        )
        self.client.force_login(user)

        response = self.client.get("/o/logout/", {"next": "/"})

        self.assertRedirects(
            response,
            "https://greenhill-auth-frontend2.onrender.com",
            fetch_redirect_response=False,
        )
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_logout_ignores_external_next_url(self):
        response = self.client.get(
            "/o/logout/",
            {"next": "https://attacker.example/"},
        )

        self.assertRedirects(
            response,
            "https://greenhill-auth-frontend2.onrender.com",
            fetch_redirect_response=False,
        )
