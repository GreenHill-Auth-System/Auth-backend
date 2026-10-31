"""OAuth 2.0 token revocation.

A browser session and an OAuth token are separate credentials. Deleting the
IdP session stops a person from *obtaining* new tokens, but a relying party
that is already holding a live access token would keep working until it
expires. In an SSO system "sign out" has to mean "the three systems lose
access now", so signing out also revokes the tokens.

Django OAuth Toolkit's models are swappable, so they are looked up through
``get_access_token_model()`` / ``get_refresh_token_model()`` rather than
imported directly.

Note that DOT 3.x has no ``revoked`` column on access tokens -- only refresh
tokens carry one. Revoking an access token therefore means deleting its row,
which is what the toolkit's own ``cleartokens`` command does.
"""

import logging

from django.utils import timezone
from oauth2_provider.models import (
    get_access_token_model,
    get_refresh_token_model,
)

logger = logging.getLogger(__name__)


def user_from_bearer_token(raw_token):
    """The account behind an ``Authorization: Bearer`` value, or ``None``.

    Sign-out needs a second way to identify the caller. The three systems are
    served from sibling ``*.onrender.com`` hosts, and that suffix is on the
    public suffix list, so a ``fetch`` from one of their pages to this service
    is a *third-party* request: the browser may withhold the session cookie
    even with ``SameSite=None``. A relying party's backend, holding the access
    token it was given, can always present it server-to-server -- and that is
    the only reliable way to revoke.

    Only a *live* token resolves. An expired one identifies nobody: accepting
    it would let a stale value force repeated sign-outs, and it cannot prove
    the presenter is the person it names.

    The lookup is by raw token text because that is what Django OAuth Toolkit
    stores in ``AccessToken.token`` (``token_checksum`` is an index built from
    it, not a replacement).
    """
    if not raw_token:
        return None

    AccessToken = get_access_token_model()

    token = (
        AccessToken.objects.select_related("user")
        .filter(token=raw_token)
        .first()
    )

    if token is None or token.expires is None:
        return None

    if token.expires <= timezone.now():
        return None

    if token.user is None or not token.user.is_active:
        return None

    return token.user


def revoke_user_tokens(user, client=None):
    """Delete every access and refresh token held for this user.

    Refresh tokens are deleted first: an access token issued *from* one points
    at it, so removing the grant before its derived tokens keeps the deletion
    order explicit instead of relying on cascade behaviour.

    Returns a dict with the number of each kind removed.
    """
    if user is None:
        return {"access_tokens": 0, "refresh_tokens": 0}

    AccessToken = get_access_token_model()
    RefreshToken = get_refresh_token_model()

    access_queryset = AccessToken.objects.filter(user=user)
    refresh_queryset = RefreshToken.objects.filter(user=user)

    if client is not None:
        access_queryset = access_queryset.filter(application=client)
        refresh_queryset = refresh_queryset.filter(application=client)

    # ``source_refresh_token`` is a one-to-one, so clearing the reference first
    # keeps the access-token delete independent of the FK's on_delete rule.
    access_count = access_queryset.count()
    access_queryset.update(source_refresh_token=None)

    refresh_count = refresh_queryset.count()
    refresh_queryset.delete()
    access_queryset.delete()

    logger.info(
        "revoked %s access and %s refresh token(s) for user %s",
        access_count,
        refresh_count,
        user.pk,
    )

    return {
        "access_tokens": access_count,
        "refresh_tokens": refresh_count,
    }


def revoke_application_tokens(user, application):
    """Revoke only the tokens a single relying party holds for this user."""
    return revoke_user_tokens(user, client=application)