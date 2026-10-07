from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


class WorkspaceDirectoryService:
    # Service for interacting with the Google Workspace Admin SDK
    # Directory API.

    def __init__(self, credentials=None, service=None):
        # Allow a pre-built service to be injected for testing.
        self.service = service or build(
            "admin",
            "directory_v1",
            credentials=credentials,
        )

    def get_user_by_email(self, email):
        # Retrieve the complete Workspace user profile so that
        # organizational information such as department and job title
        # is available for authorization.
        try:
            response = (
                self.service.users()
                .get(
                    userKey=email,
                    projection="full",
                )
                .execute()
            )
        except HttpError:
            # A missing or inaccessible Workspace user must not
            # receive application access.
            return None

        # Google stores employee organizational information in
        # the organizations collection.
        organizations = response.get("organizations") or []

        # Prefer the primary organization when multiple records exist.
        primary_organization = next(
            (
                organization
                for organization in organizations
                if organization.get("primary")
            ),
            organizations[0] if organizations else {},
        )

        name = response.get("name") or {}

        # Normalize Google's response into the structure expected
        # by the authorization layer.
        return {
            "id": response.get("id", ""),
            "email": response.get("primaryEmail", ""),
            "first_name": name.get("givenName", ""),
            "last_name": name.get("familyName", ""),
            "full_name": name.get("fullName", ""),
            "department": primary_organization.get(
                "department",
                "",
            ),
            "job_title": primary_organization.get(
                "title",
                "",
            ),
        }