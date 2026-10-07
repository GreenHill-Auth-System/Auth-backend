from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import TestCase

from authentication.authentication_gateway_factory import (
    AuthenticationGatewayConfigurationError,
    create_authentication_gateway,
    load_private_key,
    load_public_key,
)


class AuthenticationGatewayFactoryTests(TestCase):
    # Tests for creating the complete authentication gateway
    # from application configuration.

    @classmethod
    def setUpTestData(cls):
        # Generate an in-memory RSA key pair for testing.
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        cls.public_key = cls.private_key.public_key()

    @patch(
        "authentication.authentication_gateway_factory.create_delegated_credentials"
    )
    @patch(
        "authentication.authentication_gateway_factory.WorkspaceDirectoryService"
    )
    @patch(
        "authentication.authentication_gateway_factory.load_private_key"
    )
    @patch(
        "authentication.authentication_gateway_factory.load_public_key"
    )
    def test_factory_creates_authentication_gateway(
        self,
        mock_load_public_key,
        mock_load_private_key,
        mock_directory_service,
        mock_create_credentials,
    ):
        # Arrange: provide the required application configuration.
        with patch.dict(
            "os.environ",
            {
                "GOOGLE_WORKSPACE_ADMIN_EMAIL":
                    "admin@greenhillacademy.ac.ug",
                "JWT_PRIVATE_KEY_FILE":
                    "keys/private.pem",
                "JWT_PUBLIC_KEY_FILE":
                    "keys/public.pem",
                "JWT_ISSUER":
                    "greenhill-auth",
                "JWT_AUDIENCE":
                    "greenhill-systems",
            },
        ):
            mock_create_credentials.return_value = Mock()
            mock_load_private_key.return_value = self.private_key
            mock_load_public_key.return_value = self.public_key

            # Act: create the authentication gateway.
            gateway = create_authentication_gateway()

            # Assert: verify the complete gateway was created.
            self.assertIsNotNone(gateway)

            mock_create_credentials.assert_called_once_with(
                "admin@greenhillacademy.ac.ug"
            )

            mock_directory_service.assert_called_once()

            mock_load_private_key.assert_called_once_with(
                "keys/private.pem"
            )

            mock_load_public_key.assert_called_once_with(
                "keys/public.pem"
            )

    @patch(
        "authentication.authentication_gateway_factory.create_delegated_credentials"
    )
    def test_factory_requires_workspace_admin_email(
        self,
        mock_create_credentials,
    ):
        # Arrange: remove the Workspace administrator configuration.
        with patch.dict(
            "os.environ",
            {
                "GOOGLE_WORKSPACE_ADMIN_EMAIL": "",
                "JWT_PRIVATE_KEY_FILE": "keys/private.pem",
                "JWT_PUBLIC_KEY_FILE": "keys/public.pem",
            },
        ):
            # Act and assert: missing administrator configuration
            # must prevent gateway creation.
            with self.assertRaises(
                AuthenticationGatewayConfigurationError
            ):
                create_authentication_gateway()

        mock_create_credentials.assert_not_called()

    @patch(
        "authentication.authentication_gateway_factory.create_delegated_credentials"
    )
    def test_factory_requires_private_key_configuration(
        self,
        mock_create_credentials,
    ):
        # Arrange: provide Workspace configuration but no private key.
        with patch.dict(
            "os.environ",
            {
                "GOOGLE_WORKSPACE_ADMIN_EMAIL":
                    "admin@greenhillacademy.ac.ug",
                "JWT_PRIVATE_KEY_FILE": "",
                "JWT_PUBLIC_KEY_FILE": "keys/public.pem",
            },
        ):
            mock_create_credentials.return_value = Mock()

            # Act and assert: missing private key configuration
            # must prevent gateway creation.
            with self.assertRaises(
                AuthenticationGatewayConfigurationError
            ):
                create_authentication_gateway()

    @patch(
        "authentication.authentication_gateway_factory.create_delegated_credentials"
    )
    def test_factory_requires_public_key_configuration(
        self,
        mock_create_credentials,
    ):
        # Arrange: provide Workspace configuration but no public key.
        with patch.dict(
            "os.environ",
            {
                "GOOGLE_WORKSPACE_ADMIN_EMAIL":
                    "admin@greenhillacademy.ac.ug",
                "JWT_PRIVATE_KEY_FILE": "keys/private.pem",
                "JWT_PUBLIC_KEY_FILE": "",
            },
        ):
            mock_create_credentials.return_value = Mock()

            # Act and assert: missing public key configuration
            # must prevent gateway creation.
            with self.assertRaises(
                AuthenticationGatewayConfigurationError
            ):
                create_authentication_gateway()

    def test_load_private_key_from_file(self):
        # Arrange: create a temporary RSA private key file.
        private_key_data = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with TemporaryDirectory() as directory:
            key_path = Path(directory) / "private.pem"
            key_path.write_bytes(private_key_data)

            # Act: load the private key from the file.
            loaded_key = load_private_key(
                str(key_path)
            )

            # Assert: verify that the key was loaded correctly.
            self.assertEqual(
                loaded_key.private_numbers(),
                self.private_key.private_numbers(),
            )

    def test_load_public_key_from_file(self):
        # Arrange: create a temporary RSA public key file.
        public_key_data = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with TemporaryDirectory() as directory:
            key_path = Path(directory) / "public.pem"
            key_path.write_bytes(public_key_data)

            # Act: load the public key from the file.
            loaded_key = load_public_key(
                str(key_path)
            )

            # Assert: verify that the key was loaded correctly.
            self.assertEqual(
                loaded_key.public_numbers(),
                self.public_key.public_numbers(),
            )

    def test_load_private_key_rejects_invalid_file(self):
        # Arrange: create a file containing invalid key data.
        with TemporaryDirectory() as directory:
            key_path = Path(directory) / "invalid.pem"
            key_path.write_text(
                "not a valid private key"
            )

            # Act and assert: invalid key data should be rejected.
            with self.assertRaises(
                AuthenticationGatewayConfigurationError
            ):
                load_private_key(
                    str(key_path)
                )

    def test_load_public_key_rejects_invalid_file(self):
        # Arrange: create a file containing invalid key data.
        with TemporaryDirectory() as directory:
            key_path = Path(directory) / "invalid.pem"
            key_path.write_text(
                "not a valid public key"
            )

            # Act and assert: invalid key data should be rejected.
            with self.assertRaises(
                AuthenticationGatewayConfigurationError
            ):
                load_public_key(
                    str(key_path)
                )