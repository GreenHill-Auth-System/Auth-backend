"""Create `.env` from `.env.example` and fill in the secrets that must be
generated rather than chosen.

    python generate_env.py            # create .env (refuses to overwrite)
    python generate_env.py --force    # overwrite an existing .env

What it does
------------
1. Copies `.env.example` to `.env` so every variable exists with a comment
   explaining it.
2. Fills `SECRET_KEY` with a fresh 50-character Django key.
3. Fills `OIDC_RSA_PRIVATE_KEY` with a fresh 2048-bit RSA private key, in the
   multi-line double-quoted form that python-dotenv understands.

What it deliberately does NOT do
--------------------------------
Client ids and secrets for EID / Procurement / Incident are created by
`python manage.py seed_oauth_clients`, because they have to exist as rows in the
database. Google credentials come from the Google Cloud console. Nothing can
invent those for you.

This script is safe to re-run: by default it will not touch an existing `.env`,
because regenerating `OIDC_RSA_PRIVATE_KEY` invalidates every token the
provider has ever issued.
"""

import argparse
import pathlib
import sys

BASE_DIR = pathlib.Path(__file__).resolve().parent
EXAMPLE = BASE_DIR / ".env.example"
TARGET = BASE_DIR / ".env"


def django_secret_key():
    from django.core.management.utils import get_random_secret_key

    return get_random_secret_key()


def rsa_private_key_pem():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def quoted_multiline(pem):
    """python-dotenv only reads a multi-line value when it is double-quoted."""
    return '"' + pem.strip() + '"'


def set_value(text, name, value):
    """Replace the first `NAME=` line, keeping every comment around it."""
    lines = text.splitlines()
    prefix = name + "="
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            lines[index] = prefix + value
            return "\n".join(lines) + "\n"
    lines.append(prefix + value)
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing .env (invalidates issued tokens)",
    )
    args = parser.parse_args()

    if not EXAMPLE.exists():
        sys.exit(f"missing template: {EXAMPLE}")

    if TARGET.exists() and not args.force:
        sys.exit(
            f"{TARGET.name} already exists. "
            "Re-run with --force only if you accept that every issued token "
            "becomes invalid."
        )

    text = EXAMPLE.read_text(encoding="utf-8")
    text = set_value(text, "SECRET_KEY", django_secret_key())
    text = set_value(text, "OIDC_RSA_PRIVATE_KEY", quoted_multiline(rsa_private_key_pem()))
    TARGET.write_text(text, encoding="utf-8")

    print(f"wrote {TARGET}")
    print()
    print("Generated for you:")
    print("  SECRET_KEY              50 random characters")
    print("  OIDC_RSA_PRIVATE_KEY    2048-bit RSA key, signs your id_tokens")
    print()
    print("Still blank, because a machine cannot invent them:")
    print("  GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET")
    print("      https://console.cloud.google.com/apis/credentials")
    print("  EID_/PROCUREMENT_/INCIDENT_CLIENT_SECRET")
    print("      python manage.py seed_oauth_clients")
    print()


if __name__ == "__main__":
    main()
