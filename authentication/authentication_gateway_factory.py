import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from authentication.authentication_gateway import (
    AuthenticationGatewayService,
)
from authentication.authorization import AuthorizationService
from authentication.google_credentials import (
    create_delegated_credentials,
)
from authentication.jwt_service import JWTService
from authentication.workspace_directory import (
    WorkspaceDirectoryService,
)


class AuthenticationGatewayConfigurationError(Exception):
    # Raised when the authentication gateway is missing
    # required production configuration.

    pass


def load_private_key(path):
    # Load the RSA private key used to sign application JWTs.
    try:
        key_data = Path(path).read_bytes()

        return serialization.load_pem_private_key(
            key_data,
            password=None,
        )
    except Exception as exc:
        raise AuthenticationGatewayConfigurationError(
            "Unable to load the JWT private key."
        ) from exc


def load_public_key(path):
    # Load the RSA public key used to verify application JWTs.
    try:
        key_data = Path(path).read_bytes()

        return serialization.load_pem_public_key(
            key_data,
        )
    except Exception as exc:
        raise AuthenticationGatewayConfigurationError(
            "Unable to load the JWT public key."
        ) from exc


def create_authentication_gateway():
    # Read the Google Workspace administrator used for
    # Domain-Wide Delegation.
    admin_email = os.getenv(
        "GOOGLE_WORKSPACE_ADMIN_EMAIL",
        "",
    ).strip()

    if not admin_email:
        raise AuthenticationGatewayConfigurationError(
            "GOOGLE_WORKSPACE_ADMIN_EMAIL is not configured."
        )

    # Create delegated Google credentials.
    #
    # The delegated subject is the authorized Workspace administrator,
    # not the employee being authenticated.
    credentials = create_delegated_credentials(
        admin_email
    )

    # Create the Google Workspace Directory service.
    directory_service = WorkspaceDirectoryService(
        credentials=credentials
    )

    # Create the role-based authorization service.
    authorization_service = AuthorizationService()

    # Read the configured RSA key locations.
    private_key_path = os.getenv(
        "JWT_PRIVATE_KEY_FILE",
        "",
    ).strip()

    public_key_path = os.getenv(
        "JWT_PUBLIC_KEY_FILE",
        "",
    ).strip()

    if not private_key_path:
        raise AuthenticationGatewayConfigurationError(
            "JWT_PRIVATE_KEY_FILE is not configured."
        )

    if not public_key_path:
        raise AuthenticationGatewayConfigurationError(
            "JWT_PUBLIC_KEY_FILE is not configured."
        )

    # Load the RSA keys used by the application JWT service.
    private_key = load_private_key(
        private_key_path
    )

    public_key = load_public_key(
        public_key_path
    )

    # Read the JWT issuer and audience from environment configuration.
    issuer = os.getenv(
        "JWT_ISSUER",
        "greenhill-auth",
    ).strip()

    audience = os.getenv(
        "JWT_AUDIENCE",
        "greenhill-systems",
    ).strip()

    # Create the application JWT service.
    jwt_service = JWTService(
        private_key=private_key,
        public_key=public_key,
        issuer=issuer,
        audience=audience,
    )

    # Combine all authentication components into the central gateway.
    return AuthenticationGatewayService(
        directory_service=directory_service,
        authorization_service=authorization_service,
        jwt_service=jwt_service,
    )