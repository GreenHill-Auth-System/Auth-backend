from unittest.mock import patch

from django.test import TestCase


class GoogleWorkspaceCredentialsTests(TestCase):
    # Tests for creating Google Workspace credentials.
    #
    # These tests verify that the backend can create credentials
    # configured for Domain-Wide Delegation.
    #
    # Google's credential creation is mocked so that these tests do not
    # require a real service-account JSON file or Google Workspace
    # administrator configuration.

    @patch("authentication.google_credentials.service_account.Credentials")
    @patch(
        "authentication.google_credentials.SERVICE_ACCOUNT_FILE",
        "test-service-account.json",
    )
    def test_create_delegated_credentials_uses_service_account(
        self,
        mock_credentials,
    ):
        # The credentials helper should create service-account
        # credentials using the configured service-account file.

        from authentication.google_credentials import (
            create_delegated_credentials,
        )

        # Act: create delegated credentials for a Workspace administrator.
        result = create_delegated_credentials(
            subject="admin@greenhillacademy.ac.ug"
        )

        # Assert: verify that service-account credentials were created.
        mock_credentials.from_service_account_file.assert_called_once()

        # Verify that the credentials are delegated to the configured
        # Workspace administrator account.
        mock_credentials.from_service_account_file.return_value.with_subject.assert_called_once_with(
            "admin@greenhillacademy.ac.ug"
        )

        self.assertEqual(
            result,
            mock_credentials.from_service_account_file.return_value.with_subject.return_value,
        )

    @patch("authentication.google_credentials.service_account.Credentials")
    @patch(
        "authentication.google_credentials.SERVICE_ACCOUNT_FILE",
        "test-service-account.json",
    )
    def test_create_delegated_credentials_requests_directory_readonly_scope(
        self,
        mock_credentials,
    ):
        # The Directory API should use the least-privileged scope
        # required to read Workspace user information.

        from authentication.google_credentials import (
            create_delegated_credentials,
        )

        # Act: create delegated credentials.
        create_delegated_credentials(
            subject="admin@greenhillacademy.ac.ug"
        )

        # Retrieve the arguments used when creating the credentials.
        call_kwargs = (
            mock_credentials.from_service_account_file.call_args.kwargs
        )

        scopes = call_kwargs["scopes"]

        # Verify that the read-only Directory API scope is requested.
        self.assertIn(
            "https://www.googleapis.com/auth/admin.directory.user.readonly",
            scopes,
        )

    @patch("authentication.google_credentials.service_account.Credentials")
    @patch(
        "authentication.google_credentials.SERVICE_ACCOUNT_FILE",
        "test-service-account.json",
    )
    def test_create_delegated_credentials_uses_configured_service_account_file(
        self,
        mock_credentials,
    ):
        # The service-account file path should come from configuration
        # rather than being hardcoded in the application.

        from authentication.google_credentials import (
            create_delegated_credentials,
        )

        # Act: create delegated credentials.
        create_delegated_credentials(
            subject="admin@greenhillacademy.ac.ug"
        )

        # Assert: verify that the configured service-account file
        # was passed to Google's credential loader.
        mock_credentials.from_service_account_file.assert_called_once()

        call_args = (
            mock_credentials.from_service_account_file.call_args
        )

        self.assertEqual(
            call_args.args[0],
            "test-service-account.json",
        )

    @patch("authentication.google_credentials.service_account.Credentials")
    def test_create_delegated_credentials_requires_service_account_file(
        self,
        mock_credentials,
    ):
        # The application should clearly report missing service-account
        # configuration instead of attempting to create credentials.

        from authentication.google_credentials import (
            GoogleCredentialsConfigurationError,
            create_delegated_credentials,
        )

        with patch(
            "authentication.google_credentials.SERVICE_ACCOUNT_FILE",
            "",
        ):
            # Act and assert: missing configuration should raise the
            # application's configuration error.
            with self.assertRaises(
                GoogleCredentialsConfigurationError
            ) as context:
                create_delegated_credentials(
                    subject="admin@greenhillacademy.ac.ug"
                )

        # Verify that the error clearly identifies the missing setting.
        self.assertIn(
            "GOOGLE_SERVICE_ACCOUNT_FILE",
            str(context.exception),
        )

        # Google should not be called when configuration is missing.
        mock_credentials.from_service_account_file.assert_not_called()

    @patch("authentication.google_credentials.service_account.Credentials")
    def test_create_delegated_credentials_rejects_whitespace_service_account_file(
        self,
        mock_credentials,
    ):
        # Whitespace-only configuration should be treated as missing
        # configuration.

        from authentication.google_credentials import (
            GoogleCredentialsConfigurationError,
            create_delegated_credentials,
        )

        with patch(
            "authentication.google_credentials.SERVICE_ACCOUNT_FILE",
            "   ",
        ):
            # Act and assert: whitespace should raise the same
            # configuration error as an empty value.
            with self.assertRaises(
                GoogleCredentialsConfigurationError
            ):
                create_delegated_credentials(
                    subject="admin@greenhillacademy.ac.ug"
                )

        # Google should not be called when configuration is invalid.
        mock_credentials.from_service_account_file.assert_not_called()