"""Registry of the three first-party relying parties.

EID, Procurement and Incident each register as an OAuth 2.0 client of this
authorisation server. Keeping the definition here (rather than only in the
Django admin) means the three clients can be recreated on a fresh deployment
from environment variables with one command::

    python manage.py seed_oauth_clients

Each client is *confidential* (it runs on a server, so it can keep a secret)
and uses the *authorisation code* grant with PKCE, which is the only flow this
server permits. ``skip_authorization`` is on because these are first-party
applications: the person is signing in to GreenHill, not granting a third
party anything, so a consent screen would be friction with no security value.

The scope a client is allowed to request is its base identity scopes plus its
own project scope. A user still has to *hold* that scope: the per-user check
lives in ``GreenHillOAuth2Validator.validate_scopes``.
"""

import os
from dataclasses import dataclass

from authentication.access import SYSTEM_SCOPES
from authentication.models import AllowedEmail

BASE_SCOPES = ("openid", "profile", "email")


@dataclass(frozen=True)
class RelyingParty:
    """One of the three systems that trusts this identity provider."""

    key: str
    name: str
    system: str
    env_prefix: str

    @property
    def scope(self):
        """The project scope that grants access to this system."""
        return SYSTEM_SCOPES[self.system]

    @property
    def allowed_scopes(self):
        return BASE_SCOPES + (self.scope,)

    @property
    def redirect_uris_env(self):
        return f"{self.env_prefix}_REDIRECT_URIS"

    @property
    def post_logout_redirect_uris_env(self):
        return f"{self.env_prefix}_POST_LOGOUT_REDIRECT_URIS"

    @property
    def client_id_env(self):
        return f"{self.env_prefix}_CLIENT_ID"

    @property
    def client_secret_env(self):
        return f"{self.env_prefix}_CLIENT_SECRET"

    @property
    def allowed_origins_env(self):
        return f"{self.env_prefix}_ALLOWED_ORIGINS"


RELYING_PARTIES = (
    RelyingParty(
        key="eid",
        name="GreenHill EID",
        system=AllowedEmail.System.EID,
        env_prefix="EID",
    ),
    RelyingParty(
        key="procurement",
        name="GreenHill Procurement (PMS)",
        system=AllowedEmail.System.PROCUREMENT,
        env_prefix="PROCUREMENT",
    ),
    RelyingParty(
        key="incident",
        name="GreenHill Incident Management (ISMP)",
        system=AllowedEmail.System.INCIDENT,
        env_prefix="INCIDENT",
    ),
)


def _split_env(name):
    """Read a comma or whitespace separated list out of the environment.

    Accepts both ``a,b`` and ``a b`` so the value can be pasted either way, and
    strips newlines so a multi-line Render env var works too.
    """
    raw = os.getenv(name, "") or ""
    normalised = raw.replace("\n", ",").replace("\r", ",")
    parts = []
    for chunk in normalised.replace(",", " ").split():
        chunk = chunk.strip()
        if chunk and chunk not in parts:
            parts.append(chunk)
    return parts


def redirect_uris(relying_party):
    return _split_env(relying_party.redirect_uris_env)


def post_logout_redirect_uris(relying_party):
    return _split_env(relying_party.post_logout_redirect_uris_env)


def allowed_origins(relying_party):
    return _split_env(relying_party.allowed_origins_env)


def declared_client_id(relying_party):
    return (os.getenv(relying_party.client_id_env) or "").strip()


def declared_client_secret(relying_party):
    return (os.getenv(relying_party.client_secret_env) or "").strip()


def get_relying_party(key):
    """Look one up by its short key (``eid``, ``procurement``, ``incident``)."""
    for relying_party in RELYING_PARTIES:
        if relying_party.key == key:
            return relying_party
    return None
