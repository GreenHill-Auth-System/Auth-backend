from datetime import timedelta

import jwt
from django.utils import timezone


class JWTConfigurationError(Exception):
    # Raised when the JWT service is missing required configuration.

    pass


class JWTService:
    # Service responsible for creating and verifying application JWTs.

    def __init__(
        self,
        private_key,
        public_key,
        issuer,
        audience,
        expiration=timedelta(minutes=15),
    ):
        # A private key is required to sign application tokens.
        if private_key is None:
            raise JWTConfigurationError(
                "JWT private key is required."
            )

        # A public key is required to verify application tokens.
        if public_key is None:
            raise JWTConfigurationError(
                "JWT public key is required."
            )

        self.private_key = private_key
        self.public_key = public_key
        self.issuer = issuer
        self.audience = audience
        self.expiration = expiration

    def create_token(self, employee):
        # Get the employee's email because it identifies
        # the authenticated user in the application.
        email = employee.get("email", "").strip()

        # Build the JWT claims used by Greenhill systems.
        now = timezone.now()
        issued_at = int(now.timestamp())
        expires_at = int(
            (now + self.expiration).timestamp()
        )

        payload = {
            "sub": email,
            "email": email,
            "role": employee.get("role", ""),
            "authorizedSystems": employee.get(
                "authorized_systems",
                [],
            ),
            "iss": self.issuer,
            "aud": self.audience,
            "iat": issued_at,
            "exp": expires_at,
        }

        # Always explicitly use RS256.
        #
        # The algorithm is intentionally not taken from the
        # incoming token header during verification.
        return jwt.encode(
            payload,
            self.private_key,
            algorithm="RS256",
        )

    def verify_token(self, token):
        # Verify the signature and enforce the expected
        # issuer, audience, and RS256 algorithm.
        return jwt.decode(
            token,
            self.public_key,
            algorithms=["RS256"],
            issuer=self.issuer,
            audience=self.audience,
        )