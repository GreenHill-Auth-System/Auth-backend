from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from authentication.domain_guard import is_greenhill_email


class GoogleLoginTests(TestCase):

    # Tests for initiating Google OAuth 2.0 / OpenID Connect authentication.
    # These tests verify that the authentication gateway:
    # - Redirects users to Google's authorization endpoint.
    # - Generates and stores OAuth state for CSRF protection.
    # - Generates and stores a PKCE code verifier.
    # - Includes the PKCE challenge in the Google authorization request.

    @patch("authentication.views.os.getenv")
    def test_google_login_redirects_to_google(self, mock_getenv):
        mock_getenv.side_effect = lambda key, default=None: {
            "GOOGLE_CLIENT_ID": "test-client-id",
            "GOOGLE_CLIENT_SECRET": "test-client-secret",
            "GOOGLE_REDIRECT_URI": (
                "http://localhost:8000/auth/google/callback/"
            ),
        }.get(key, default)

        response = self.client.get(reverse("google_login"))

        self.assertEqual(response.status_code, 302)
        self.assertIn("accounts.google.com", response.url)

    @patch("authentication.views.os.getenv")
    def test_google_login_stores_oauth_state(self, mock_getenv):
        mock_getenv.side_effect = lambda key, default=None: {
            "GOOGLE_CLIENT_ID": "test-client-id",
            "GOOGLE_CLIENT_SECRET": "test-client-secret",
            "GOOGLE_REDIRECT_URI": (
                "http://localhost:8000/auth/google/callback/"
            ),
        }.get(key, default)

        self.client.get(reverse("google_login"))

        self.assertIn(
            "google_oauth_state",
            self.client.session,
        )
        self.assertTrue(
            self.client.session["google_oauth_state"]
        )

    @patch("authentication.views.os.getenv")
    def test_google_login_stores_code_verifier(self, mock_getenv):
        mock_getenv.side_effect = lambda key, default=None: {
            "GOOGLE_CLIENT_ID": "test-client-id",
            "GOOGLE_CLIENT_SECRET": "test-client-secret",
            "GOOGLE_REDIRECT_URI": (
                "http://localhost:8000/auth/google/callback/"
            ),
        }.get(key, default)

        self.client.get(reverse("google_login"))

        self.assertIn(
            "google_code_verifier",
            self.client.session,
        )
        self.assertTrue(
            self.client.session["google_code_verifier"]
        )

    @patch("authentication.views.os.getenv")
    def test_google_login_includes_pkce_challenge(self, mock_getenv):
        mock_getenv.side_effect = lambda key, default=None: {
            "GOOGLE_CLIENT_ID": "test-client-id",
            "GOOGLE_CLIENT_SECRET": "test-client-secret",
            "GOOGLE_REDIRECT_URI": (
                "http://localhost:8000/auth/google/callback/"
            ),
        }.get(key, default)

        response = self.client.get(reverse("google_login"))

        self.assertIn(
            "code_challenge=",
            response.url,
        )
        self.assertIn(
            "code_challenge_method=S256",
            response.url,
        )


class GreenHillDomainGuardTests(TestCase):

    # Tests for the GreenHill Workspace domain restriction.
    # Only users whose Google account belongs to the official
    # GreenHill Workspace domain are permitted to authenticate.

    def test_greenhill_email_is_allowed(self):
        self.assertTrue(
            is_greenhill_email(
                "employee@greenhillacademy.ac.ug"
            )
        )

    def test_greenhill_email_check_is_case_insensitive(self):
        self.assertTrue(
            is_greenhill_email(
                "EMPLOYEE@GREENHILLACADEMY.AC.UG"
            )
        )

    def test_gmail_account_is_rejected(self):
        self.assertFalse(
            is_greenhill_email(
                "employee@gmail.com"
            )
        )

    def test_old_greenhill_domain_is_rejected(self):
        self.assertFalse(
            is_greenhill_email(
                "employee@greenhill.edu"
            )
        )

    def test_similar_domain_is_rejected(self):
        self.assertFalse(
            is_greenhill_email(
                "employee@greenhillacademy.ac.ug.com"
            )
        )

    def test_malicious_domain_is_rejected(self):
        self.assertFalse(
            is_greenhill_email(
                "employee@greenhillacademy.ac.ug.evil.com"
            )
        )

    def test_missing_email_is_rejected(self):
        self.assertFalse(
            is_greenhill_email("")
        )

    def test_none_email_is_rejected(self):
        self.assertFalse(
            is_greenhill_email(None)
        )


class GoogleCallbackSecurityTests(TestCase):

    # Tests for security controls applied to the OAuth callback.
    # The callback requires both:
    # - OAuth state, which protects against CSRF attacks.
    # - PKCE code verifier, which protects the authorization code exchange.

    def test_callback_rejects_missing_oauth_state(self):
        response = self.client.get(
            reverse("google_callback")
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "OAuth state is missing from the session.",
            response.content.decode(),
        )

    def test_callback_rejects_missing_code_verifier(self):
        session = self.client.session
        session["google_oauth_state"] = "test-state"
        session.save()

        response = self.client.get(
            reverse("google_callback"),
            {"state": "test-state"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "OAuth code verifier is missing from the session.",
            response.content.decode(),
        )

    def test_callback_rejects_invalid_oauth_state(self):
        session = self.client.session
        session["google_oauth_state"] = "valid-state"
        session["google_code_verifier"] = "test-verifier"
        session.save()

        response = self.client.get(
            reverse("google_callback"),
            {"state": "invalid-state"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "Invalid OAuth state.",
            response.content.decode(),
        )


class GoogleCallbackDomainGuardTests(TestCase):

    # Tests that the OAuth callback enforces the GreenHill Workspace
    # domain restriction after Google identity verification.

    @patch("authentication.views.id_token.verify_oauth2_token")
    @patch("authentication.views.Flow")
    @patch("authentication.views.os.getenv")
    def test_non_greenhill_account_redirects_to_login_with_error(
        self,
        mock_getenv,
        mock_flow_class,
        mock_verify_token,
    ):
        mock_getenv.side_effect = lambda key, default=None: {
            "GOOGLE_CLIENT_ID": "test-client-id",
            "GOOGLE_CLIENT_SECRET": "test-client-secret",
            "GOOGLE_REDIRECT_URI": (
                "http://localhost:8000/auth/google/callback/"
            ),
            "FRONTEND_URL": "http://localhost:5173",
        }.get(key, default)

        mock_flow = (
            mock_flow_class.from_client_config.return_value
        )
        mock_flow.credentials.id_token = "mock-id-token"

        mock_verify_token.return_value = {
            "email": "testuser@gmail.com",
            "name": "Test User",
        }

        session = self.client.session
        session["google_oauth_state"] = "test-state"
        session["google_code_verifier"] = "test-verifier"
        session.save()

        response = self.client.get(
            reverse("google_callback"),
            {
                "state": "test-state",
                "code": "test-code",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url,
            "http://localhost:5173/?error=greenhill_account_required",
        )

    @patch("authentication.views.id_token.verify_oauth2_token")
    @patch("authentication.views.Flow")
    @patch("authentication.views.os.getenv")
    def test_greenhill_account_is_accepted(
        self,
        mock_getenv,
        mock_flow_class,
        mock_verify_token,
    ):
        mock_getenv.side_effect = lambda key, default=None: {
            "GOOGLE_CLIENT_ID": "test-client-id",
            "GOOGLE_CLIENT_SECRET": "test-client-secret",
            "GOOGLE_REDIRECT_URI": (
                "http://localhost:8000/auth/google/callback/"
            ),
            "FRONTEND_URL": "http://localhost:5173",
        }.get(key, default)

        mock_flow = (
            mock_flow_class.from_client_config.return_value
        )
        mock_flow.credentials.id_token = "mock-id-token"

        mock_verify_token.return_value = {
            "email": "employee@greenhillacademy.ac.ug",
            "name": "GreenHill Employee",
        }

        session = self.client.session
        session["google_oauth_state"] = "test-state"
        session["google_code_verifier"] = "test-verifier"
        session.save()

        response = self.client.get(
            reverse("google_callback"),
            {
                "state": "test-state",
                "code": "test-code",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url,
            "http://localhost:5173/workspaces",
        )

        self.assertEqual(
            self.client.session["authenticated_user"],
            {
                "email": "employee@greenhillacademy.ac.ug",
                "name": "GreenHill Employee",
                "role": "Greenhill User",
                "authorized_systems": [
                    "EID",
                    "Procurement",
                    "Incident Service Management",
                ],
            },
        )


class GoogleAuthenticationApiResponseTests(TestCase):

    # Tests the authentication callback response used by the frontend.
    # A successful GreenHill Google authentication creates the local
    # Django session and redirects the user to the React workspace.
    # A non-GreenHill account is redirected back to the login page
    # with an error code.

    @patch("authentication.views.id_token.verify_oauth2_token")
    @patch("authentication.views.Flow")
    @patch("authentication.views.os.getenv")
    def test_successful_authentication_redirects_to_workspace(
        self,
        mock_getenv,
        mock_flow_class,
        mock_verify_token,
    ):
        mock_getenv.side_effect = lambda key, default=None: {
            "GOOGLE_CLIENT_ID": "test-client-id",
            "GOOGLE_CLIENT_SECRET": "test-client-secret",
            "GOOGLE_REDIRECT_URI": (
                "http://localhost:8000/auth/google/callback/"
            ),
            "FRONTEND_URL": "http://localhost:5173",
        }.get(key, default)

        mock_flow = (
            mock_flow_class.from_client_config.return_value
        )
        mock_flow.credentials.id_token = "mock-id-token"

        mock_verify_token.return_value = {
            "email": "employee@greenhillacademy.ac.ug",
            "name": "GreenHill Employee",
        }

        session = self.client.session
        session["google_oauth_state"] = "test-state"
        session["google_code_verifier"] = "test-verifier"
        session.save()

        response = self.client.get(
            reverse("google_callback"),
            {
                "state": "test-state",
                "code": "test-code",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url,
            "http://localhost:5173/workspaces",
        )

        self.assertEqual(
            self.client.session["authenticated_user"],
            {
                "email": "employee@greenhillacademy.ac.ug",
                "name": "GreenHill Employee",
                "role": "Greenhill User",
                "authorized_systems": [
                    "EID",
                    "Procurement",
                    "Incident Service Management",
                ],
            },
        )

    @patch("authentication.views.id_token.verify_oauth2_token")
    @patch("authentication.views.Flow")
    @patch("authentication.views.os.getenv")
    def test_rejected_account_redirects_to_login_with_error(
        self,
        mock_getenv,
        mock_flow_class,
        mock_verify_token,
    ):
        mock_getenv.side_effect = lambda key, default=None: {
            "GOOGLE_CLIENT_ID": "test-client-id",
            "GOOGLE_CLIENT_SECRET": "test-client-secret",
            "GOOGLE_REDIRECT_URI": (
                "http://localhost:8000/auth/google/callback/"
            ),
            "FRONTEND_URL": "http://localhost:5173",
        }.get(key, default)

        mock_flow = (
            mock_flow_class.from_client_config.return_value
        )
        mock_flow.credentials.id_token = "mock-id-token"

        mock_verify_token.return_value = {
            "email": "testuser@gmail.com",
            "name": "Test User",
        }

        session = self.client.session
        session["google_oauth_state"] = "test-state"
        session["google_code_verifier"] = "test-verifier"
        session.save()

        response = self.client.get(
            reverse("google_callback"),
            {
                "state": "test-state",
                "code": "test-code",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url,
            "http://localhost:5173/?error=greenhill_account_required",
        )


class GoogleIdTokenVerificationTests(TestCase):

    # Tests for Google ID token verification.
    # The backend must verify the ID token with Google's verification
    # mechanism before trusting any identity information contained in it.

    @patch("authentication.views.id_token.verify_oauth2_token")
    @patch("authentication.views.Flow")
    @patch("authentication.views.os.getenv")
    def test_invalid_google_id_token_is_rejected(
        self,
        mock_getenv,
        mock_flow_class,
        mock_verify_token,
    ):
        mock_getenv.side_effect = lambda key, default=None: {
            "GOOGLE_CLIENT_ID": "test-client-id",
            "GOOGLE_CLIENT_SECRET": "test-secret",
            "GOOGLE_REDIRECT_URI": (
                "http://localhost:8000/auth/google/callback/"
            ),
        }.get(key, default)

        mock_flow = (
            mock_flow_class.from_client_config.return_value
        )
        mock_flow.credentials.id_token = "invalid-id-token"

        mock_verify_token.side_effect = ValueError(
            "Invalid Google ID token"
        )

        session = self.client.session
        session["google_oauth_state"] = "test-state"
        session["google_code_verifier"] = "test-verifier"
        session.save()

        response = self.client.get(
            reverse("google_callback"),
            {
                "state": "test-state",
                "code": "test-code",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "Google ID token verification failed:",
            response.content.decode(),
        )


class LocalUserAuthenticationTests(TestCase):

    # Tests for creating and authenticating a local application user
    # after successful Google Workspace identity verification.
    # Google remains the identity provider, while Django maintains the
    # application's local authenticated user session.

    def test_new_google_user_is_created_locally(self):

        # A verified GreenHill Workspace user should have a corresponding
        # local Django user account.

        email = "employee@greenhillacademy.ac.ug"
        name = "GreenHill Employee"

        User = get_user_model()

        user, created = User.objects.get_or_create(
            username=email,
            defaults={
                "email": email,
                "first_name": name,
            },
        )

        self.assertTrue(created)
        self.assertEqual(user.email, email)
        self.assertEqual(user.first_name, name)

    def test_existing_google_user_is_reused(self):

        # A returning Google user should reuse the existing local account
        # instead of creating a duplicate user.

        User = get_user_model()

        email = "employee@greenhillacademy.ac.ug"

        existing_user = User.objects.create_user(
            username=email,
            email=email,
            first_name="GreenHill Employee",
        )

        user, created = User.objects.get_or_create(
            username=email,
            defaults={
                "email": email,
                "first_name": "GreenHill Employee",
            },
        )

        self.assertFalse(created)
        self.assertEqual(
            user.id,
            existing_user.id,
        )

    def test_local_user_can_be_authenticated(self):

        # A valid local user should be able to establish an authenticated
        # Django session.

        User = get_user_model()

        user = User.objects.create_user(
            username="employee@greenhillacademy.ac.ug",
            email="employee@greenhillacademy.ac.ug",
            password="test-password",
        )

        authenticated = self.client.login(
            username="employee@greenhillacademy.ac.ug",
            password="test-password",
        )

        self.assertTrue(authenticated)
        self.assertEqual(
            int(self.client.session["_auth_user_id"]),
            user.id,
        )

    def test_rejected_google_account_does_not_create_local_user(self):

        # A Google account outside the GreenHill Workspace domain must not
        # result in a local application user being created.

        User = get_user_model()

        email = "testuser@gmail.com"

        self.assertFalse(
            is_greenhill_email(email)
        )

        self.assertFalse(
            User.objects.filter(username=email).exists()
        )


class GoogleCallbackLocalUserTests(TestCase):

    # Tests that a successfully verified GreenHill Workspace identity
    # is connected to a local Django user and authenticated session.
    # Google remains the identity provider. Django maintains the local
    # application user and session after Google identity verification.

    @patch("authentication.views.id_token.verify_oauth2_token")
    @patch("authentication.views.Flow")
    @patch("authentication.views.os.getenv")
    def test_successful_google_login_creates_local_user_and_session(
        self,
        mock_getenv,
        mock_flow_class,
        mock_verify_token,
    ):

        # A first-time GreenHill Workspace user should be created locally
        # and authenticated into the Django session.

        mock_getenv.side_effect = lambda key, default=None: {
            "GOOGLE_CLIENT_ID": "test-client-id",
            "GOOGLE_CLIENT_SECRET": "test-client-secret",
            "GOOGLE_REDIRECT_URI": (
                "http://localhost:8000/auth/google/callback/"
            ),
            "FRONTEND_URL": "http://localhost:5173",
        }.get(key, default)

        mock_flow = (
            mock_flow_class.from_client_config.return_value
        )
        mock_flow.credentials.id_token = "mock-id-token"

        mock_verify_token.return_value = {
            "email": "employee@greenhillacademy.ac.ug",
            "name": "GreenHill Employee",
        }

        session = self.client.session
        session["google_oauth_state"] = "test-state"
        session["google_code_verifier"] = "test-verifier"
        session.save()

        response = self.client.get(
            reverse("google_callback"),
            {
                "state": "test-state",
                "code": "test-code",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url,
            "http://localhost:5173/workspaces",
        )

        User = get_user_model()

        self.assertTrue(
            User.objects.filter(
                email="employee@greenhillacademy.ac.ug"
            ).exists()
        )

        user = User.objects.get(
            email="employee@greenhillacademy.ac.ug"
        )

        self.assertEqual(
            user.first_name,
            "GreenHill Employee",
        )

        self.assertEqual(
            int(self.client.session["_auth_user_id"]),
            user.id,
        )

        self.assertEqual(
            self.client.session["authenticated_user"],
            {
                "email": "employee@greenhillacademy.ac.ug",
                "name": "GreenHill Employee",
                "role": "Greenhill User",
                "authorized_systems": [
                    "EID",
                    "Procurement",
                    "Incident Service Management",
                ],
            },
        )

    @patch("authentication.views.id_token.verify_oauth2_token")
    @patch("authentication.views.Flow")
    @patch("authentication.views.os.getenv")
    def test_returning_google_user_reuses_existing_local_user(
        self,
        mock_getenv,
        mock_flow_class,
        mock_verify_token,
    ):

        # A returning GreenHill Workspace user should reuse the existing
        # local account rather than creating a duplicate.

        User = get_user_model()

        existing_user = User.objects.create_user(
            username="employee@greenhillacademy.ac.ug",
            email="employee@greenhillacademy.ac.ug",
            first_name="GreenHill Employee",
        )

        mock_getenv.side_effect = lambda key, default=None: {
            "GOOGLE_CLIENT_ID": "test-client-id",
            "GOOGLE_CLIENT_SECRET": "test-client-secret",
            "GOOGLE_REDIRECT_URI": (
                "http://localhost:8000/auth/google/callback/"
            ),
            "FRONTEND_URL": "http://localhost:5173",
        }.get(key, default)

        mock_flow = (
            mock_flow_class.from_client_config.return_value
        )
        mock_flow.credentials.id_token = "mock-id-token"

        mock_verify_token.return_value = {
            "email": "employee@greenhillacademy.ac.ug",
            "name": "GreenHill Employee",
        }

        session = self.client.session
        session["google_oauth_state"] = "test-state"
        session["google_code_verifier"] = "test-verifier"
        session.save()

        response = self.client.get(
            reverse("google_callback"),
            {
                "state": "test-state",
                "code": "test-code",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url,
            "http://localhost:5173/workspaces",
        )

        self.assertEqual(
            User.objects.filter(
                email="employee@greenhillacademy.ac.ug"
            ).count(),
            1,
        )

        self.assertEqual(
            int(self.client.session["_auth_user_id"]),
            existing_user.id,
        )

        self.assertEqual(
            self.client.session["authenticated_user"],
            {
                "email": "employee@greenhillacademy.ac.ug",
                "name": "GreenHill Employee",
                "role": "Greenhill User",
                "authorized_systems": [
                    "EID",
                    "Procurement",
                    "Incident Service Management",
                ],
            },
        )


class ManualLoginTests(TestCase):

    # Tests for the manual email/password authentication endpoint.
    # The backend is responsible for validating credentials and returning
    # structured responses that the frontend can display to the user.

    def test_missing_email_and_password_returns_required_fields_error(self):
        response = self.client.post(
            reverse("manual_login"),
            data={},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)

        self.assertEqual(
            response.json(),
            {
                "authenticated": False,
                "error": "required_fields",
                "message": (
                    "Please enter your Greenhill Workspace credentials."
                ),
                "fields": {
                    "email": True,
                    "password": True,
                },
            },
        )

    def test_missing_email_returns_required_fields_error(self):
        response = self.client.post(
            reverse("manual_login"),
            data={
                "password": "test-password",
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)

        self.assertEqual(
            response.json()["error"],
            "required_fields",
        )

        self.assertEqual(
            response.json()["fields"],
            {
                "email": True,
                "password": False,
            },
        )

    def test_missing_password_returns_required_fields_error(self):
        response = self.client.post(
            reverse("manual_login"),
            data={
                "email": "employee@greenhillacademy.ac.ug",
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)

        self.assertEqual(
            response.json()["error"],
            "required_fields",
        )

        self.assertEqual(
            response.json()["fields"],
            {
                "email": False,
                "password": True,
            },
        )

    def test_non_greenhill_email_is_rejected(self):
        response = self.client.post(
            reverse("manual_login"),
            data={
                "email": "employee@gmail.com",
                "password": "test-password",
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)

        self.assertEqual(
            response.json(),
            {
                "authenticated": False,
                "error": "greenhill_email_required",
                "message": (
                    "Please use your Greenhill Academy work email "
                    "address to sign in."
                ),
                "fields": {
                    "email": True,
                    "password": False,
                },
            },
        )

    def test_incorrect_password_returns_invalid_credentials_error(self):
        User = get_user_model()

        User.objects.create_user(
            username="employee@greenhillacademy.ac.ug",
            email="employee@greenhillacademy.ac.ug",
            password="correct-password",
        )

        response = self.client.post(
            reverse("manual_login"),
            data={
                "email": "employee@greenhillacademy.ac.ug",
                "password": "wrong-password",
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 401)

        self.assertEqual(
            response.json(),
            {
                "authenticated": False,
                "error": "invalid_credentials",
                "message": (
                    "Incorrect email or password. "
                    "Please check your credentials and try again."
                ),
                "fields": {
                    "email": True,
                    "password": True,
                },
            },
        )

    def test_unknown_greenhill_email_returns_invalid_credentials_error(self):
        response = self.client.post(
            reverse("manual_login"),
            data={
                "email": "unknown@greenhillacademy.ac.ug",
                "password": "wrong-password",
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 401)

        self.assertEqual(
            response.json()["error"],
            "invalid_credentials",
        )

        self.assertEqual(
            response.json()["fields"],
            {
                "email": True,
                "password": True,
            },
        )

    def test_correct_credentials_create_authenticated_session(self):
        User = get_user_model()

        user = User.objects.create_user(
            username="employee@greenhillacademy.ac.ug",
            email="employee@greenhillacademy.ac.ug",
            first_name="GreenHill Employee",
            password="correct-password",
        )

        response = self.client.post(
            reverse("manual_login"),
            data={
                "email": "employee@greenhillacademy.ac.ug",
                "password": "correct-password",
                "remember": True,
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)

        self.assertEqual(
            response.json(),
            {
                "authenticated": True,
                "user": {
                    "email": "employee@greenhillacademy.ac.ug",
                    "name": "GreenHill Employee",
                    "role": "Greenhill User",
                    "authorized_systems": [
                        "EID",
                        "Procurement",
                        "Incident Service Management",
                    ],
                },
            },
        )

        self.assertEqual(
            int(self.client.session["_auth_user_id"]),
            user.id,
        )

        self.assertEqual(
            self.client.session["authenticated_user"],
            {
                "email": "employee@greenhillacademy.ac.ug",
                "name": "GreenHill Employee",
                "role": "Greenhill User",
                "authorized_systems": [
                    "EID",
                    "Procurement",
                    "Incident Service Management",
                ],
            },
        )

    def test_manual_login_accepts_uppercase_greenhill_email(self):
        User = get_user_model()

        User.objects.create_user(
            username="employee@greenhillacademy.ac.ug",
            email="employee@greenhillacademy.ac.ug",
            password="correct-password",
        )

        response = self.client.post(
            reverse("manual_login"),
            data={
                "email": "EMPLOYEE@GREENHILLACADEMY.AC.UG",
                "password": "correct-password",
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.json()["authenticated"]
        )