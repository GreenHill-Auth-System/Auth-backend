import os

from google.oauth2 import service_account


# Google Workspace Admin SDK scope required to read Workspace users.
#
# We use the read-only scope because this application only needs to
# retrieve employee information from the Workspace Directory.
GOOGLE_DIRECTORY_READONLY_SCOPE = (
    "https://www.googleapis.com/auth/admin.directory.user.readonly"
)


# The service-account JSON file path is loaded from the environment
# instead of being hardcoded in the application.
#
# This keeps sensitive configuration outside the source code.
SERVICE_ACCOUNT_FILE = os.getenv(
    "GOOGLE_SERVICE_ACCOUNT_FILE",
    "",
).strip()


class GoogleCredentialsConfigurationError(Exception):
    # Raised when the Google Workspace credentials configuration
    # required by the application is missing or invalid.

    pass


def create_delegated_credentials(subject):
    # Remove accidental whitespace from the configured file path.
    service_account_file = SERVICE_ACCOUNT_FILE.strip()

    # Verify that the service-account file has been configured
    # before attempting to create Google credentials.
    if not service_account_file:
        raise GoogleCredentialsConfigurationError(
            "GOOGLE_SERVICE_ACCOUNT_FILE is not configured."
        )

    # Create Google service-account credentials with the Directory API
    # read-only scope.
    #
    # Domain-Wide Delegation allows the service account to act on behalf
    # of an authorized GreenHill Workspace administrator.
    credentials = service_account.Credentials.from_service_account_file(
        service_account_file,
        scopes=[
            GOOGLE_DIRECTORY_READONLY_SCOPE,
        ],
    )

    # Delegate the credentials to the specified Workspace account.
    return credentials.with_subject(subject)