from datetime import timedelta

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import TestCase
from django.utils import timezone

from authentication.jwt_service import (
    JWTConfigurationError,
    JWTService,
)


class JWTServiceTests(TestCase):
    # Generate an RSA key pair in memory for testing.
    #
    # These keys are intentionally not stored in the repository.
    @classmethod
    def setUpTestData(cls):
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        cls.public_key = cls.private_key.public_key()

        cls.service = JWTService(
            private_key=cls.private_key,
            public_key=cls.public_key,
            issuer="greenhill-auth",
            audience="greenhill-systems",
        )

    def test_create_token_contains_expected_claims(self):
        # Arrange: provide the authorization information for an employee.
        employee = {
            "email": "finance.director@greenhillacademy.ac.ug",
            "role": "Finance Director",
            "authorized_systems": [
                "EID",
                "Procurement",
            ],
        }

        # Act: create an application JWT.
        token = self.service.create_token(employee)

        # Decode the token using the test public key.
        payload = jwt.decode(
            token,
            self.public_key,
            algorithms=["RS256"],
            audience="greenhill-systems",
            issuer="greenhill-auth",
        )

        # Assert: verify the identity and authorization claims.
        self.assertEqual(
            payload["sub"],
            "finance.director@greenhillacademy.ac.ug",
        )

        self.assertEqual(
            payload["email"],
            "finance.director@greenhillacademy.ac.ug",
        )

        self.assertEqual(
            payload["role"],
            "Finance Director",
        )

        self.assertEqual(
            payload["authorizedSystems"],
            [
                "EID",
                "Procurement",
            ],
        )

    def test_create_token_uses_rs256_algorithm(self):
        # Arrange: provide employee authorization information.
        employee = {
            "email": "finance.director@greenhillacademy.ac.ug",
            "role": "Finance Director",
            "authorized_systems": [
                "EID",
                "Procurement",
            ],
        }

        # Act: create the JWT.
        token = self.service.create_token(employee)

        # Read the token header without verifying the signature.
        header = jwt.get_unverified_header(token)

        # Assert: the application uses asymmetric RS256 signing.
        self.assertEqual(
            header["alg"],
            "RS256",
        )

    def test_create_token_contains_issuer_and_audience(self):
        # Arrange: provide employee authorization information.
        employee = {
            "email": "finance.director@greenhillacademy.ac.ug",
            "role": "Finance Director",
            "authorized_systems": [
                "EID",
                "Procurement",
            ],
        }

        # Act: create the JWT.
        token = self.service.create_token(employee)

        # Decode and verify the token.
        payload = jwt.decode(
            token,
            self.public_key,
            algorithms=["RS256"],
            audience="greenhill-systems",
            issuer="greenhill-auth",
        )

        # Assert: verify issuer and audience claims.
        self.assertEqual(
            payload["iss"],
            "greenhill-auth",
        )

        self.assertEqual(
            payload["aud"],
            "greenhill-systems",
        )

    def test_create_token_contains_expiration(self):
        # Arrange: provide employee authorization information.
        employee = {
            "email": "finance.director@greenhillacademy.ac.ug",
            "role": "Finance Director",
            "authorized_systems": [
                "EID",
                "Procurement",
            ],
        }

        # Act: create the JWT.
        token = self.service.create_token(employee)

        # Decode the token while disabling only expiration validation.
        #
        # Issuer and audience validation remain enabled.
        payload = jwt.decode(
            token,
            self.public_key,
            algorithms=["RS256"],
            audience="greenhill-systems",
            issuer="greenhill-auth",
            options={
                "verify_exp": False,
            },
        )

        # Assert: the token contains an expiration timestamp.
        self.assertIn(
            "exp",
            payload,
        )

        self.assertGreater(
            payload["exp"],
            int(timezone.now().timestamp()),
        )

    def test_verify_token_returns_payload_for_valid_token(self):
        # Arrange: create a valid employee JWT.
        employee = {
            "email": "finance.director@greenhillacademy.ac.ug",
            "role": "Finance Director",
            "authorized_systems": [
                "EID",
                "Procurement",
            ],
        }

        token = self.service.create_token(employee)

        # Act: verify the JWT using the public key.
        payload = self.service.verify_token(token)

        # Assert: verified claims are returned.
        self.assertEqual(
            payload["email"],
            "finance.director@greenhillacademy.ac.ug",
        )

        self.assertEqual(
            payload["role"],
            "Finance Director",
        )

    def test_verify_token_rejects_expired_token(self):
        # Arrange: create a service that issues already-expired tokens.
        expired_service = JWTService(
            private_key=self.private_key,
            public_key=self.public_key,
            issuer="greenhill-auth",
            audience="greenhill-systems",
            expiration=timedelta(seconds=-1),
        )

        employee = {
            "email": "finance.director@greenhillacademy.ac.ug",
            "role": "Finance Director",
            "authorized_systems": [
                "EID",
                "Procurement",
            ],
        }

        token = expired_service.create_token(employee)

        # Act and assert: expired tokens must be rejected.
        with self.assertRaises(jwt.ExpiredSignatureError):
            self.service.verify_token(token)

    def test_verify_token_rejects_wrong_issuer(self):
        # Arrange: create a token with an unexpected issuer.
        wrong_issuer_service = JWTService(
            private_key=self.private_key,
            public_key=self.public_key,
            issuer="unexpected-service",
            audience="greenhill-systems",
        )

        employee = {
            "email": "finance.director@greenhillacademy.ac.ug",
            "role": "Finance Director",
            "authorized_systems": [
                "EID",
                "Procurement",
            ],
        }

        token = wrong_issuer_service.create_token(employee)

        # Act and assert: the configured issuer must be enforced.
        with self.assertRaises(jwt.InvalidIssuerError):
            self.service.verify_token(token)

    def test_verify_token_rejects_wrong_audience(self):
        # Arrange: create a token with an unexpected audience.
        wrong_audience_service = JWTService(
            private_key=self.private_key,
            public_key=self.public_key,
            issuer="greenhill-auth",
            audience="unexpected-system",
        )

        employee = {
            "email": "finance.director@greenhillacademy.ac.ug",
            "role": "Finance Director",
            "authorized_systems": [
                "EID",
                "Procurement",
            ],
        }

        token = wrong_audience_service.create_token(employee)

        # Act and assert: the configured audience must be enforced.
        with self.assertRaises(jwt.InvalidAudienceError):
            self.service.verify_token(token)

    def test_jwt_service_requires_private_key(self):
        # The service should not operate without a signing key.
        with self.assertRaises(JWTConfigurationError):
            JWTService(
                private_key=None,
                public_key=self.public_key,
                issuer="greenhill-auth",
                audience="greenhill-systems",
            )

    def test_jwt_service_requires_public_key(self):
        # The service should not operate without a verification key.
        with self.assertRaises(JWTConfigurationError):
            JWTService(
                private_key=self.private_key,
                public_key=None,
                issuer="greenhill-auth",
                audience="greenhill-systems",
            )