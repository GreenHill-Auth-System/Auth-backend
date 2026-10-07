from django.test import TestCase

from authentication.authorization import AuthorizationService


class AuthorizationServiceTests(TestCase):
    # Tests for determining a Greenhill employee's role
    # and the systems they are allowed to access.

    def test_finance_director_has_finance_and_procurement_access(self):
        # Arrange: provide employee information for a Finance Director.
        employee = {
            "email": "finance.director@greenhillacademy.ac.ug",
            "department": "Finance",
            "job_title": "Finance Director",
        }

        # Act: determine the employee's authorization.
        result = AuthorizationService().authorize(employee)

        # Assert: verify the employee's role and authorized systems.
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

    def test_procurement_manager_has_procurement_and_eid_access(self):
        # Arrange: provide employee information for a Procurement Manager.
        employee = {
            "email": "procurement@greenhillacademy.ac.ug",
            "department": "Procurement",
            "job_title": "Procurement Manager",
        }

        # Act: determine the employee's authorization.
        result = AuthorizationService().authorize(employee)

        # Assert: verify the employee's role and authorized systems.
        self.assertEqual(
            result["role"],
            "Procurement Manager",
        )

        self.assertEqual(
            result["authorized_systems"],
            [
                "EID",
                "Procurement",
            ],
        )

    def test_operations_service_manager_has_incident_service_and_eid_access(
        self,
    ):
        # Arrange: provide employee information for an Operations Service Manager.
        employee = {
            "email": "operations@greenhillacademy.ac.ug",
            "department": "Operations",
            "job_title": "Operations Service Manager",
        }

        # Act: determine the employee's authorization.
        result = AuthorizationService().authorize(employee)

        # Assert: verify the employee's role and authorized systems.
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

    def test_head_teacher_has_incident_service_and_eid_access(self):
        # Arrange: provide employee information for a Head Teacher.
        employee = {
            "email": "head.teacher@greenhillacademy.ac.ug",
            "department": "Academic",
            "job_title": "Head Teacher",
        }

        # Act: determine the employee's authorization.
        result = AuthorizationService().authorize(employee)

        # Assert: verify the employee's role and authorized systems.
        self.assertEqual(
            result["role"],
            "Head Teacher",
        )

        self.assertEqual(
            result["authorized_systems"],
            [
                "EID",
                "Incident Service Management",
            ],
        )

    def test_unknown_role_has_no_authorized_systems(self):
        # Arrange: provide an employee whose role is not configured.
        employee = {
            "email": "employee@greenhillacademy.ac.ug",
            "department": "Unknown",
            "job_title": "Unknown",
        }

        # Act: determine the employee's authorization.
        result = AuthorizationService().authorize(employee)

        # Assert: unknown roles should not receive system access.
        self.assertEqual(
            result["role"],
            "Unknown",
        )

        self.assertEqual(
            result["authorized_systems"],
            [],
        )

    def test_missing_employee_information_is_rejected(self):
        # Arrange: provide incomplete employee information.
        employee = {
            "email": "employee@greenhillacademy.ac.ug",
        }

        # Act and assert: incomplete information should raise an error.
        with self.assertRaises(ValueError):
            AuthorizationService().authorize(employee)