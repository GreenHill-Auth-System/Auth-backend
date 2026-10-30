"""Identity plumbing: turning an email or a Google subject into a ``User``.

Kept separate from ``views`` so the same rules apply to every entry point
(Google callback, password login, admin seeding). The rules are:

* Email is the identity key, compared case-insensitively and stored lower-cased.
* A database-level unique index on ``LOWER(auth_user.email)`` enforces it
  (migration ``0005``), so a race between two logins cannot create duplicates.
* A Google ``sub`` maps to exactly one local user. If a second Google account
  ever presents the same ``sub``, that is an attack, not a merge.
"""

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction

from authentication.models import GoogleIdentity

# Domain-segment suffix used to reject non-GreenHill workspaces, plus the
# shared address normalisation so every module trims and lower-cases the same
# way.
from authentication.domain_guard import GREENHILL_DOMAIN, normalize_email  # noqa: F401


def find_user_by_email(email):
    """Return the user with this email, or ``None``.

    Uses ``iexact`` so a differently-cased row still matches, and orders by
    primary key so the result is deterministic if a legacy duplicate exists.

    An empty address always returns ``None``: many accounts have a blank
    ``email``, and matching on it would let any of them sign in.
    """
    email = normalize_email(email)
    if not email:
        return None

    User = get_user_model()
    return (
        User.objects.filter(email__iexact=email)
        .order_by("pk")
        .first()
    )


def get_or_create_user_by_email(email, name=""):
    """Return ``(user, created)`` for an email address.

    Safe under concurrency: if another request inserts the same email between
    the lookup and the insert, the unique index rejects it, the transaction
    rolls back, and the existing row is returned instead of raising.
    """
    email = normalize_email(email)

    existing = find_user_by_email(email)
    if existing is not None:
        return existing, False

    User = get_user_model()

    try:
        with transaction.atomic():
            user = User(username=email, email=email)
            if name:
                user.first_name = name
            user.set_unusable_password()
            user.save()
            return user, True
    except IntegrityError:
        # Lost the race (or the username collided). Re-read the winner.
        existing = find_user_by_email(email)
        if existing is not None:
            return existing, False
        raise


def link_google_identity(user, claims):
    """Record the verified Google account behind ``user``.

    ``claims`` is the verified id_token payload. Returns the ``GoogleIdentity``.

    Raises ``ValueError`` if the Google subject is already linked to a different
    local user, because that means an email was reassigned inside Google and the
    two accounts must not be merged silently.
    """
    subject = (claims.get("sub") or "").strip()
    if not subject:
        raise ValueError("Google response has no subject claim.")

    identity = GoogleIdentity.objects.filter(google_sub=subject).first()

    if identity is not None and identity.user_id != user.pk:
        raise ValueError(
            "This Google account is already linked to a different user."
        )

    if identity is None:
        identity = GoogleIdentity(user=user, google_sub=subject)

    identity.user = user
    identity.email_verified = bool(claims.get("email_verified"))
    identity.hosted_domain = (claims.get("hd") or "").strip().lower()
    identity.google_email = normalize_email(claims.get("email"))
    identity.save()

    return identity


def google_claims_are_trustworthy(claims):
    """Return ``(ok, reason)`` for a verified id_token payload.

    Two independent assertions must hold before the claims can be used as an
    identity:

    1. ``email_verified`` — Google has proven the caller controls the address.
       Without it, a Workspace admin could assert an unverified address.
    2. ``hd`` (when present) — the account belongs to the GreenHill Workspace.
       Google only emits ``hd`` for Workspace accounts of the requested domain.
    """
    if claims.get("email_verified") is not True:
        return False, "email_not_verified"

    hosted_domain = (claims.get("hd") or "").strip().lower()
    if hosted_domain:
        expected = GREENHILL_DOMAIN.lstrip("@").lower()
        if hosted_domain != expected:
            return False, "wrong_hosted_domain"

    return True, ""


def resolve_google_user(claims):
    """Return ``(user, created)`` for a verified Google sign-in.

    Resolution order matters. The Google subject is checked *before* any local
    account is created, so a repeated or conflicting subject can never leave a
    stray ``auth.User`` row behind.

    * Known subject  -> that user, even if Google has since changed the address
      (a surname change is a legitimate rename, and the subject did not change).
    * New subject    -> the user owning the address, or a newly created one.

    Raises ``ValueError`` when the identity cannot be reconciled; the caller
    decides what to tell the browser.
    """
    subject = (claims.get("sub") or "").strip()
    if not subject:
        raise ValueError("Google response has no subject claim.")

    email = normalize_email(claims.get("email"))
    name = claims.get("name") or ""

    identity = GoogleIdentity.objects.filter(google_sub=subject).first()

    if identity is not None:
        user = identity.user

        if normalize_email(user.email) != email:
            clash = find_user_by_email(email)
            if clash is not None and clash.pk != user.pk:
                raise ValueError(
                    "That address now belongs to a different account."
                )
            try:
                with transaction.atomic():
                    user.email = email
                    user.save(update_fields=["email"])
            except IntegrityError as exc:
                raise ValueError(
                    "That address is already in use."
                ) from exc

        identity = link_google_identity(user, claims)
        return identity.user, False

    user, created = get_or_create_user_by_email(email, name)
    link_google_identity(user, claims)
    return user, created
