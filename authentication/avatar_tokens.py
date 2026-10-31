"""Self-authenticating URLs for avatars.

The three systems live on three origins, and ``onrender.com`` is a public
suffix, so ``greenhill-auth-backend2.onrender.com`` and
``pms-frontend-4fm8.onrender.com`` are different *sites* -- not merely different
origins. An ``<img src="https://greenhill-auth-backend2.../auth/avatar/">`` on the
PMS page is therefore a **third-party** request, and the only session cookie
that can currently authorise it is ``SameSite=None``, which browsers are
throttling, partitioning or blocking outright.

The visible result: ``/auth/me/`` says the person has a picture, and the image
still 404s in the two systems that are not the auth app -- three systems, three
different-looking profiles, with nothing wrong in any database row.

So the URL carries its own proof. ``/auth/avatar/`` accepts either the normal
signed-in session (same-origin use, unchanged) **or** a token that names the
account and expires. A token is a capability: whoever holds the URL can fetch
that one image until it expires, which is the same trade every signed media
URL makes. It only ever reveals one person's avatar, and the URL is reissued by
``/auth/me/`` on every page load, so the window stays short.

This module exists so the view and the OIDC claims build the URL the same way;
they previously duplicated the format and could drift apart.
"""

from django.core import signing
from django.contrib.auth import get_user_model

# Distinct from every other signing salt in the project, so a token minted for
# one purpose can never be replayed against another.
AVATAR_SALT = "authentication.avatar"

# Long enough to render a page and its cached subresources, short enough that a
# leaked URL stops working the same day.
AVATAR_TOKEN_MAX_AGE = 60 * 60 * 24


def _signer():
    return signing.TimestampSigner(salt=AVATAR_SALT)


def issue_avatar_token(user):
    """A signed, expiring token naming this account."""
    return _signer().sign_object({"u": user.pk})


def resolve_avatar_token(token):
    """The account id a token names, or ``None`` if it is not usable.

    Expired, tampered, truncated and other-purpose tokens all return ``None``:
    a URL is a hostile input, and none of those cases should raise.
    """
    token = (token or "").strip()

    if not token:
        return None

    try:
        payload = _signer().unsign_object(token, max_age=AVATAR_TOKEN_MAX_AGE)
    except (signing.BadSignature, signing.SignatureExpired, ValueError, TypeError):
        return None

    if not isinstance(payload, dict):
        return None

    user_pk = payload.get("u")

    if not isinstance(user_pk, int):
        return None

    return user_pk


def avatar_path(profile, user):
    """The callback-relative URL for this person's avatar, or ``""``.

    ``v`` is the avatar's last-modified time and is purely a cache-buster: a
    replaced image gets a new URL, so a browser that cached the old one cannot
    keep showing it.
    """
    if profile is None or not profile.has_avatar:
        return ""

    version = int(profile.updated_at.timestamp())
    return f"/auth/avatar/?v={version}&t={issue_avatar_token(user)}"


def avatar_user_from_token(token):
    """The account a token names, if it still exists and may be shown."""
    user_pk = resolve_avatar_token(token)

    if user_pk is None:
        return None

    return get_user_model().objects.filter(pk=user_pk, is_active=True).first()
