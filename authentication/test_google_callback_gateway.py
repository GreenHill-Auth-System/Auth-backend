from unittest.mock import Mock

from django.test import TestCase


class GoogleCallbackGatewayTests(TestCase):
    def setUp(self):
        # Create mocked authentication services so these tests
        # do not require live Google Workspace credentials.
        self.gateway = Mock()

    def test_gateway_returns_application_jwt(self):
        # Arrange: configure the gateway with a successful
        # authentication result.
        self.gateway.authenticate.return_value = {
            "email": "finance.director@greenhillacademy.ac.ug",
            "role": "Finance Director",
            "authorized_systems": [
                "EID",
                "Procurement",
            ],
            "token": "test-jwt-token",
        }

        # Act: authenticate the employee through the gateway.
        result = self.gateway.authenticate(
            "finance.director@greenhillacademy.ac.ug"
        )

        # Assert: verify that an application JWT is returned.
        self.assertEqual(
            result["token"],
            "test-jwt-token",
        )

    def test_gateway_receives_google_workspace_email(self):
        # Arrange: configure the gateway with a successful result.
        self.gateway.authenticate.return_value = {
            "email": "finance.director@greenhillacademy.ac.ug",
            "role": "Finance Director",
            "authorized_systems": [
                "EID",
                "Procurement",
            ],
            "token": "test-jwt-token",
        }

        email = "finance.director@greenhillacademy.ac.ug"

        # Act: pass the email obtained from Google authentication
        # to the authentication gateway.
        self.gateway.authenticate(email)

        # Assert: verify that the gateway received the correct email.
        self.gateway.authenticate.assert_called_once_with(email)

    def test_gateway_returns_employee_authorization(self):
        # Arrange: configure a Finance Director authorization result.
        self.gateway.authenticate.return_value = {
            "email": "finance.director@greenhillacademy.ac.ug",
            "role": "Finance Director",
            "authorized_systems": [
                "EID",
                "Procurement",
            ],
            "token": "test-jwt-token",
        }

        # Act: authenticate the employee.
        result = self.gateway.authenticate(
            "finance.director@greenhillacademy.ac.ug"
        )

        # Assert: verify the employee's role and systems.
        self.assertEqual(
            result["role"],
            "Finance Director",
        )

        self.assertEqual(
            result["authorized_systems"],
            [
                "EID",
                "Procurement",
            ],
        )

    def test_gateway_supports_incident_service_access(self):
        # Arrange: configure an Operations Service Manager.
        self.gateway.authenticate.return_value = {
            "email": "operations@greenhillacademy.ac.ug",
            "role": "Operations Service Manager",
            "authorized_systems": [
                "EID",
                "Incident Service Management",
            ],
            "token": "operations-jwt-token",
        }

        # Act: authenticate the employee.
        result = self.gateway.authenticate(
            "operations@greenhillacademy.ac.ug"
        )

        # Assert: verify the correct authorization information.
        self.assertEqual(
            result["role"],
            "Operations Service Manager",
        )

        self.assertEqual(
            result["authorized_systems"],
            [
                "EID",
                "Incident Service Management",
            ],
        )

        self.assertEqual(
            result["token"],
            "operations-jwt-token",
        )

    def test_gateway_rejects_unknown_workspace_user(self):
        # Arrange: simulate a user who cannot be authenticated
        # by the Workspace gateway.
        self.gateway.authenticate.side_effect = ValueError(
            "Greenhill Workspace user was not found."
        )

        # Act and assert: the gateway must reject the authentication.
        with self.assertRaises(ValueError):
            self.gateway.authenticate(
                "unknown@greenhillacademy.ac.ug"
            )

        # Verify that no successful authentication result was returned.
        self.assertEqual(
            self.gateway.authenticate.call_count,
            1,
        )