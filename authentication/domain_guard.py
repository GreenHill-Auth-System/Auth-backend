"""GreenHill email format rules.

Every GreenHill staff member has an address of exactly this shape::

    <local-part>@greenhillacademy.ac.ug

for example::

    cnmusisi@greenhillacademy.ac.ug

Only the part before the ``@`` changes; the domain is always ours. That makes
the local part the staff member's identifier, and the address itself the key
we hang roles and project access off.

Because the local part is typed by hand at the sign-in form, it is the only
place a hostile value could be smuggled into the system (``cnmusisi+eid@...``,
``cnmusisi@evil.example@greenhillacademy.ac.ug``, unicode homoglyphs, embedded
whitespace, quoted strings). It is therefore validated as strictly as the
domain rather than with a loose "ends with our domain" test.

Two levels of check exist, on purpose:

``is_greenhill_email``
    "Is this address inside our domain at all?" A suffix test. Used where the
    address has already been asserted by a trusted third party (Google
    Workspace, which must additionally assert ``email_verified`` and the ``hd``
    claim), so an over-strict pattern can never lock a real staff member out of
    the Google path.

``is_valid_greenhill_email``
    Full structural validation of ``<local-part>@greenhillacademy.ac.ug``,
    used for anything a person types by hand and for anything we persist as an
    access-control key (``AllowedEmail`` rows).
"""

import re

from django.core.exceptions import ValidationError

GREENHILL_DOMAIN = "@greenhillacademy.ac.ug"
GREENHILL_DOMAIN_NAME = GREENHILL_DOMAIN.lstrip("@")

# A conservative staff-identifier pattern:
#   * begins with a letter (identifiers are initials + surname)
#   * lower case only, because every address is normalised before it is tested
#   * segments may be joined by exactly one ".", "_" or "-"
#   * never two separators in a row, never a separator at either end
#   * no "+tags", no spaces, no quotes, no unicode
LOCAL_PART_PATTERN = r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*"

GREENHILL_EMAIL_PATTERN = (
    r"^" + LOCAL_PART_PATTERN + re.escape(GREENHILL_DOMAIN) + r"$"
)

GREENHILL_EMAIL_PATTERN_REGEX = re.compile(GREENHILL_EMAIL_PATTERN)

GREENHILL_EMAIL_EXAMPLE = "cnmusisi" + GREENHILL_DOMAIN

GREENHILL_EMAIL_HINT = (
    "Use your GreenHill work email, for example "
    f"{GREENHILL_EMAIL_EXAMPLE}. Only the name before the @ varies."
)


def normalize_email(email):
    """Lower-case and trim an address so comparisons are stable."""
    return (email or "").strip().lower()


def greenhill_local_part(email):
    """Return the staff identifier before the @, or ``""`` if none.

    >>> greenhill_local_part("cnmusisi@greenhillacademy.ac.ug")
    'cnmusisi'
    """
    normalized = normalize_email(email)
    if not normalized.endswith(GREENHILL_DOMAIN):
        return ""
    return normalized[: -len(GREENHILL_DOMAIN)]


def is_greenhill_email(email):
    if not email:
        return False

    return normalize_email(email).endswith(GREENHILL_DOMAIN)


def is_valid_greenhill_email(email):
    """True only for a well-formed ``<local-part>@greenhillacademy.ac.ug``.

    Rejects ``+`` aliasing, unicode, whitespace, doubled or edge separators,
    and any other domain entirely.
    """
    if not email:
        return False

    return GREENHILL_EMAIL_PATTERN_REGEX.match(
        normalize_email(email)
    ) is not None


def validate_greenhill_email(email):
    """Return the normalised address, or raise ``ValidationError``.

    Raises with ``code="required"`` for blank input, ``code="wrong_domain"``
    when the address is not on the GreenHill domain at all, and
    ``code="bad_format"`` when the domain matches but the local part does not
    follow the ``firstname.lastname``-style convention.
    """
    normalised = normalize_email(email)

    if not normalised:
        raise ValidationError(
            "Enter your GreenHill Academy email address. " + GREENHILL_EMAIL_HINT,
            code="required",
        )

    if not is_greenhill_email(normalised):
        raise ValidationError(
            "This is not a GreenHill Academy email address. "
            + GREENHILL_EMAIL_HINT,
            code="wrong_domain",
        )

    if not is_valid_greenhill_email(normalised):
        raise ValidationError(
            "This GreenHill email address is not in the expected format "
            f"({GREENHILL_EMAIL_EXAMPLE}). " + GREENHILL_EMAIL_HINT,
            code="bad_format",
        )

    return normalised