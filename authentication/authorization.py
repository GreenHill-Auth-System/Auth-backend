class AuthorizationService:
    # Maps Greenhill employee roles to the systems they are allowed
    # to access.
    ROLE_SYSTEM_ACCESS = {
        "Finance Director": [
            "EID",
            "Procurement",
        ],
        "Procurement Manager": [
            "EID",
            "Procurement",
        ],
        "Operations Service Manager": [
            "EID",
            "Incident Service Management",
        ],
        "Head Teacher": [
            "EID",
            "Incident Service Management",
        ],
    }

    def authorize(self, employee):
        # Employee information must contain a job title.
        if not employee.get("job_title"):
            raise ValueError("Employee job title is required.")

        # Get the employee's role from their Workspace information.
        role = employee.get("job_title", "Unknown")

        # Find the systems assigned to this role.
        # Unknown roles receive no system access by default.
        authorized_systems = self.ROLE_SYSTEM_ACCESS.get(
            role,
            [],
        )

        return {
            "email": employee.get("email", ""),
            "role": role,
            "authorized_systems": authorized_systems,
        }