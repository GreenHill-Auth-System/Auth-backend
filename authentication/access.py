"""Single source of truth for GreenHill access policy.

Roles and project access are *not* stored on the Django user. They live in
``AllowedEmail``, keyed on the staff member's GreenHill address, so that:

* access can be granted before the person ever signs in,
* access can be revoked without touching the account,
* the policy survives a rename of the underlying ``auth.User`` row,
* the OIDC claims and the relying parties all read the same answer.

An address with no active ``AllowedEmail`` row is not an error. It signs in
successfully, receives no project scopes, and is reported as a plain
``Greenhill User`` -- that is the "signed in but not yet provisioned" state.

Nothing outside this module may hardcode a role, an address, or a system list.
"""

from authentication.domain_guard import normalize_email
from authentication.models import AllowedEmail

# Maps an AllowedEmail.System value to the OIDC scope that grants it.
# These strings must match ``OAUTH2_PROVIDER["SCOPES"]`` exactly.
SYSTEM_SCOPES = {
    AllowedEmail.System.EID: "eid",
    AllowedEmail.System.PROCUREMENT: "procurement",
    AllowedEmail.System.INCIDENT: "incident",
}

# Every signed-in person may request these; they carry identity, not access to
# a system. Withholding them would break sign-in itself.
BASE_SCOPES = frozenset({"openid", "profile", "email"})

# Users with no AllowedEmail row get no systems.
UNLISTED_ROLE = "Greenhill User"


def get_user_access(email):
    """Return the role and systems granted to an email address."""
    entry = AllowedEmail.objects.filter(
        email=normalize_email(email),
        is_active=True,
    ).first()

    if entry is None:
        return {"role": UNLISTED_ROLE, "authorized_systems": []}

    return {
        "role": entry.role,
        "authorized_systems": list(entry.authorized_systems or []),
    }


def get_granted_scopes(email):
    """Return the *project* scopes this address may be issued (no base scopes)."""
    return {
        SYSTEM_SCOPES[system]
        for system in get_user_access(email)["authorized_systems"]
        if system in SYSTEM_SCOPES
    }


def get_allowed_scopes(email):
    """Everything the address may put in an OIDC ``scope`` parameter."""
    return BASE_SCOPES | get_granted_scopes(email)


def split_requested_scopes(email, requested_scopes):
    """Split a requested scope set into ``(allowed, denied)``."""
    requested = {scope for scope in (requested_scopes or []) if scope}
    allowed = get_allowed_scopes(email)
    return requested & allowed, requested - allowed