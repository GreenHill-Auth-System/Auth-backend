from unittest.mock import Mock

from django.test import TestCase

from authentication.workspace_directory import (
    WorkspaceDirectoryService,
)


class WorkspaceDirectoryServiceTests(TestCase):
    # Tests for retrieving and normalizing Google Workspace
    # employee information.

    def setUp(self):
        # Create mocked Google Directory API objects so these tests
        # do not require a real GreenHill Workspace connection.
        self.service = Mock()

        self.users = Mock()
        self.user = Mock()

        self.service.users.return_value = self.users
        self.users.get.return_value = self.user

        self.directory = WorkspaceDirectoryService(
            service=self.service
        )

    def test_get_user_by_email_returns_workspace_identity(self):
        # Arrange: simulate a Google Workspace user response.
        self.user.execute.return_value = {
            "id": "workspace-user-123",
            "primaryEmail":
                "finance.director@greenhillacademy.ac.ug",
            "name": {
                "givenName": "Finance",
                "familyName": "Director",
                "fullName": "Finance Director",
            },
            "organizations": [
                {
                    "primary": True,
                    "department": "Finance",
                    "title": "Finance Director",
                }
            ],
        }

        # Act: retrieve the employee by Workspace email.
        result = self.directory.get_user_by_email(
            "finance.director@greenhillacademy.ac.ug"
        )

        # Assert: verify the normalized identity information.
        self.assertEqual(
            result["id"],
            "workspace-user-123",
        )

        self.assertEqual(
            result["email"],
            "finance.director@greenhillacademy.ac.ug",
        )

        self.assertEqual(
            result["first_name"],
            "Finance",
        )

        self.assertEqual(
            result["last_name"],
            "Director",
        )

        self.assertEqual(
            result["full_name"],
            "Finance Director",
        )

    def test_get_user_by_email_returns_department(self):
        # Arrange: simulate an employee with organizational data.
        self.user.execute.return_value = {
            "primaryEmail":
                "finance.director@greenhillacademy.ac.ug",
            "organizations": [
                {
                    "primary": True,
                    "department": "Finance",
                    "title": "Finance Director",
                }
            ],
        }

        # Act: retrieve the employee.
        result = self.directory.get_user_by_email(
            "finance.director@greenhillacademy.ac.ug"
        )

        # Assert: verify the department is returned.
        self.assertEqual(
            result["department"],
            "Finance",
        )

    def test_get_user_by_email_returns_job_title(self):
        # Arrange: simulate an employee with a job title.
        self.user.execute.return_value = {
            "primaryEmail":
                "procurement@greenhillacademy.ac.ug",
            "organizations": [
                {
                    "primary": True,
                    "department": "Procurement",
                    "title": "Procurement Manager",
                }
            ],
        }

        # Act: retrieve the employee.
        result = self.directory.get_user_by_email(
            "procurement@greenhillacademy.ac.ug"
        )

        # Assert: verify the job title is returned.
        self.assertEqual(
            result["job_title"],
            "Procurement Manager",
        )

    def test_primary_organization_is_preferred(self):
        # Arrange: simulate multiple organizational records.
        self.user.execute.return_value = {
            "primaryEmail":
                "operations@greenhillacademy.ac.ug",
            "organizations": [
                {
                    "primary": False,
                    "department": "Other",
                    "title": "Other Role",
                },
                {
                    "primary": True,
                    "department": "Operations",
                    "title": "Operations Service Manager",
                },
            ],
        }

        # Act: retrieve the employee.
        result = self.directory.get_user_by_email(
            "operations@greenhillacademy.ac.ug"
        )

        # Assert: verify that the primary organization was selected.
        self.assertEqual(
            result["department"],
            "Operations",
        )

        self.assertEqual(
            result["job_title"],
            "Operations Service Manager",
        )

    def test_missing_organization_information_returns_empty_values(
        self,
    ):
        # Arrange: simulate a Workspace user without organization data.
        self.user.execute.return_value = {
            "primaryEmail":
                "employee@greenhillacademy.ac.ug",
        }

        # Act: retrieve the employee.
        result = self.directory.get_user_by_email(
            "employee@greenhillacademy.ac.ug"
        )

        # Assert: missing organization data should not cause
        # the Directory service to fail.
        self.assertEqual(
            result["department"],
            "",
        )

        self.assertEqual(
            result["job_title"],
            "",
        )

    def test_get_user_by_email_uses_full_projection(self):
        # Arrange: simulate a successful Workspace response.
        self.user.execute.return_value = {
            "primaryEmail":
                "employee@greenhillacademy.ac.ug",
        }

        # Act: retrieve the employee.
        self.directory.get_user_by_email(
            "employee@greenhillacademy.ac.ug"
        )

        # Assert: request the full Workspace user profile.
        self.users.get.assert_called_once_with(
            userKey="employee@greenhillacademy.ac.ug",
            projection="full",
        )

    def test_get_user_by_email_returns_none_when_google_api_fails(
        self,
    ):
        # Arrange: simulate a Google Directory API failure.
        from googleapiclient.errors import HttpError

        response = Mock()
        response.status = 404

        self.user.execute.side_effect = HttpError(
            response,
            b"User not found",
        )

        # Act: retrieve the employee.
        result = self.directory.get_user_by_email(
            "unknown@greenhillacademy.ac.ug"
        )

        # Assert: inaccessible users should return None.
        self.assertIsNone(result)