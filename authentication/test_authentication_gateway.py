from unittest.mock import Mock

from django.test import TestCase

from authentication.authentication_gateway import (
    AuthenticationGatewayService,
)


class AuthenticationGatewayServiceTests(TestCase):
    def setUp(self):
        # Create mocked dependencies so these tests do not
        # require a real Google Workspace connection or RSA keys.
        self.directory_service = Mock()
        self.authorization_service = Mock()
        self.jwt_service = Mock()

        self.gateway = AuthenticationGatewayService(
            directory_service=self.directory_service,
            authorization_service=self.authorization_service,
            jwt_service=self.jwt_service,
        )

    def test_gateway_retrieves_employee_from_workspace_directory(self):
        # Arrange: provide a Google Workspace employee.
        self.directory_service.get_user_by_email.return_value = {
            "id": "workspace-user-123",
            "email": "finance.director@greenhillacademy.ac.ug",
            "first_name": "Finance",
            "last_name": "Director",
            "full_name": "Finance Director",
            "department": "Finance",
            "job_title": "Finance Director",
        }

        self.authorization_service.authorize.return_value = {
            "email": "finance.director@greenhillacademy.ac.ug",
            "role": "Finance Director",
            "authorized_systems": [
                "EID",
                "Procurement",
            ],
        }

        self.jwt_service.create_token.return_value = "test-jwt-token"

        # Act: authenticate the employee through the gateway.
        self.gateway.authenticate(
            "finance.director@greenhillacademy.ac.ug"
        )

        # Assert: verify that the Directory API was queried.
        self.directory_service.get_user_by_email.assert_called_once_with(
            "finance.director@greenhillacademy.ac.ug"
        )

    def test_gateway_uses_authorization_service(self):
        # Arrange: provide employee information.
        employee = {
            "id": "workspace-user-123",
            "email": "finance.director@greenhillacademy.ac.ug",
            "first_name": "Finance",
            "last_name": "Director",
            "full_name": "Finance Director",
            "department": "Finance",
            "job_title": "Finance Director",
        }

        self.directory_service.get_user_by_email.return_value = employee

        authorization = {
            "email": "finance.director@greenhillacademy.ac.ug",
            "role": "Finance Director",
            "authorized_systems": [
                "EID",
                "Procurement",
            ],
        }

        self.authorization_service.authorize.return_value = authorization
        self.jwt_service.create_token.return_value = "test-jwt-token"

        # Act: authenticate the employee.
        self.gateway.authenticate(
            "finance.director@greenhillacademy.ac.ug"
        )

        # Assert: the employee information was passed to authorization.
        self.authorization_service.authorize.assert_called_once_with(
            employee
        )

    def test_gateway_creates_jwt_from_authorization_result(self):
        # Arrange: provide employee information.
        employee = {
            "id": "workspace-user-123",
            "email": "finance.director@greenhillacademy.ac.ug",
            "first_name": "Finance",
            "last_name": "Director",
            "full_name": "Finance Director",
            "department": "Finance",
            "job_title": "Finance Director",
        }

        authorization = {
            "email": "finance.director@greenhillacademy.ac.ug",
            "role": "Finance Director",
            "authorized_systems": [
                "EID",
                "Procurement",
            ],
        }

        self.directory_service.get_user_by_email.return_value = employee
        self.authorization_service.authorize.return_value = authorization
        self.jwt_service.create_token.return_value = "test-jwt-token"

        # Act: authenticate the employee.
        result = self.gateway.authenticate(
            "finance.director@greenhillacademy.ac.ug"
        )

        # Assert: JWT creation uses the authorization result.
        self.jwt_service.create_token.assert_called_once_with(
            authorization
        )

        self.assertEqual(
            result["token"],
            "test-jwt-token",
        )

    def test_gateway_returns_authorization_information(self):
        # Arrange: provide employee and authorization information.
        employee = {
            "id": "workspace-user-123",
            "email": "finance.director@greenhillacademy.ac.ug",
            "first_name": "Finance",
            "last_name": "Director",
            "full_name": "Finance Director",
            "department": "Finance",
            "job_title": "Finance Director",
        }

        authorization = {
            "email": "finance.director@greenhillacademy.ac.ug",
            "role": "Finance Director",
            "authorized_systems": [
                "EID",
                "Procurement",
            ],
        }

        self.directory_service.get_user_by_email.return_value = employee
        self.authorization_service.authorize.return_value = authorization
        self.jwt_service.create_token.return_value = "test-jwt-token"

        # Act: authenticate the employee.
        result = self.gateway.authenticate(
            "finance.director@greenhillacademy.ac.ug"
        )

        # Assert: verify the complete authentication result.
        self.assertEqual(
            result["email"],
            "finance.director@greenhillacademy.ac.ug",
        )

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

        self.assertEqual(
            result["token"],
            "test-jwt-token",
        )

    def test_gateway_rejects_unknown_workspace_user(self):
        # Arrange: simulate a user that does not exist in Workspace.
        self.directory_service.get_user_by_email.return_value = None

        # Act and assert: authentication must be rejected.
        with self.assertRaises(ValueError):
            self.gateway.authenticate(
                "unknown@greenhillacademy.ac.ug"
            )

        # Authorization must not run when the user does not exist.
        self.authorization_service.authorize.assert_not_called()

        # A JWT must not be created for an unknown user.
        self.jwt_service.create_token.assert_not_called()