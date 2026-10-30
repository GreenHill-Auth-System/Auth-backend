"""Session manager: inventory, tracking and revocation.

Terminology, because "session" is overloaded in an SSO system:

**The IdP session**
    The Django session cookie on the auth domain. It is what makes single
    sign-on work: it answers "is this person already signed in?" so the three
    systems do not prompt again. Managed here.

**A relying-party session**
    Whatever EID / Procurement / Incident keep locally after they receive
    tokens. This module never touches those directly; it kills them by
    revoking the OAuth tokens behind them (see ``authentication.tokens``) and
    by deleting the IdP session so no new tokens can be minted.

Everything in this module works on the second thing: the browser sessions the
account currently holds on the auth domain.
"""

import logging

from django.conf import settings
from django.contrib.sessions.models import Session
from django.utils import timezone

from authentication.models import UserSession

logger = logging.getLogger(__name__)

# How long a tracked session may go before ``last_seen_at`` is rewritten.
# One write per request would be a needless database round-trip on every page
# load across the three frontends.
DEFAULT_TOUCH_INTERVAL = 60

# Cap on the stored User-Agent so a hostile header cannot bloat the row.
USER_AGENT_MAX_LENGTH = 400


def _touch_interval():
    return getattr(
        settings,
        "SESSION_TOUCH_INTERVAL",
        DEFAULT_TOUCH_INTERVAL,
    )


def client_ip(request):
    """Best-effort client address, honouring the proxy header Render sets."""
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        # The first entry is the original client; the rest are proxies.
        candidate = forwarded.split(",")[0].strip()
        if candidate:
            return candidate

    return request.META.get("REMOTE_ADDR") or None


def client_user_agent(request):
    return (request.META.get("HTTP_USER_AGENT") or "")[:USER_AGENT_MAX_LENGTH]


def session_user(session):
    """The account recorded in a Django session, or ``None``.

    This is the reliable answer to "who is this browser?" for two reasons:
    the session is signed by the server, and ``request.user`` cannot be
    trusted underneath a DRF view that opted out of authentication -- DRF
    resets ``request.user`` to ``AnonymousUser`` in that case.
    """
    from django.contrib.auth import get_user_model

    user_id = None
    if session is not None:
        getter = getattr(session, "get", None)
        if callable(getter):
            user_id = getter("_auth_user_id")

    if not user_id:
        return None

    try:
        return get_user_model().objects.filter(pk=user_id).first()
    except (TypeError, ValueError):
        return None


def session_exists(session_key):
    """True when the session table still holds data for this key.

    This reads the session table directly rather than going through the
    configured store. ``SESSION_ENGINE`` is pinned to the database backend
    precisely so sessions can be revoked server-side, and the row in this table
    is what a browser's cookie resolves against.
    """
    if not session_key:
        return False

    return Session.objects.filter(session_key=session_key).exists()


def destroy_session(session_key):
    """Delete the server-side session row for this key.

    Returns ``True`` when a row was actually removed. This is the only thing
    that truly signs a browser out: once the row is gone, the cookie it holds
    no longer resolves to a session on its next request.
    """
    if not session_key:
        return False

    deleted, _ = Session.objects.filter(session_key=session_key).delete()
    return deleted > 0


def track_session(request, user=None, *, force=False):
    """Create or refresh the ``UserSession`` row for this browser session.

    Must run *after* ``django.contrib.auth.login()``, because ``login()``
    cycles the session key: a row keyed on the pre-login key would never be
    found again.

    Returns the row, or ``None`` when there is nothing to track (anonymous
    request, session not yet saved, or the row was refreshed too recently).
    """
    session = getattr(request, "session", None)
    session_key = getattr(session, "session_key", None)
    if not session_key:
        # The session has not been persisted yet, so there is no key to mirror.
        return None

    user = user or getattr(request, "user", None)
    if user is None or not user.is_authenticated:
        # A DRF view that opts out of authentication resets ``request.user``
        # to AnonymousUser, so fall back to the signed session.
        user = session_user(session)
    if user is None:
        return None

    now = timezone.now()
    row = UserSession.objects.filter(session_key=session_key).first()

    if row is None:
        try:
            return UserSession.objects.create(
                user=user,
                session_key=session_key,
                ip_address=client_ip(request),
                user_agent=client_user_agent(request),
                last_seen_at=now,
            )
        except Exception:
            # A duplicate key here means a concurrent request created it first.
            logger.debug("session row already created", exc_info=True)
            return UserSession.objects.filter(session_key=session_key).first()

    if not force:
        age = (now - row.last_seen_at).total_seconds()
        if age < _touch_interval() and row.user_id == user.pk:
            return None

    row.user = user
    row.last_seen_at = now
    row.ip_address = client_ip(request)
    row.user_agent = client_user_agent(request)
    row.revoked_at = None
    row.save(
        update_fields=[
            "user",
            "last_seen_at",
            "ip_address",
            "user_agent",
            "revoked_at",
        ]
    )
    return row


def current_session_key(request):
    """The session key of the request being handled, if any."""
    return getattr(request.session, "session_key", None)


def active_sessions(user):
    """Every session the account currently holds, newest first."""
    return UserSession.objects.filter(
        user=user,
        revoked_at__isnull=True,
    ).order_by("-last_seen_at")


def revoke_session(user_session):
    """Sign one browser out.

    Deletes the Django session row (so the cookie in that browser stops
    resolving to anything) and marks the inventory row revoked.

    Returns ``True`` when a session was actually destroyed.
    """
    destroyed = destroy_session(user_session.session_key)

    user_session.revoked_at = timezone.now()
    user_session.save(update_fields=["revoked_at"])
    return destroyed


def revoke_session_by_key(session_key, user=None):
    """Revoke a single session identified by its key."""
    if not session_key:
        return False

    row = UserSession.objects.filter(session_key=session_key).first()

    if row is not None:
        if user is not None and row.user_id != user.pk:
            # Somebody else's session. Refuse rather than end it.
            return False
        return revoke_session(row)

    # No inventory row (for example a session created before this feature
    # shipped) -- still destroy the session itself.
    return destroy_session(session_key)


def revoke_other_sessions(user, keep_session_key=None):
    """Sign the account out everywhere except this browser."""
    revoked = 0
    for row in active_sessions(user):
        if keep_session_key and row.session_key == keep_session_key:
            continue
        if revoke_session(row):
            revoked += 1
    return revoked


def revoke_all_sessions(user):
    """Sign the account out on every browser, including this one."""
    return revoke_other_sessions(user, keep_session_key=None)


def serialize_session(user_session, current_key=None):
    """A JSON-safe description of one session, for the API."""
    return {
        "id": user_session.pk,
        "ip_address": user_session.ip_address,
        "user_agent": user_session.user_agent,
        "created_at": user_session.created_at.isoformat(),
        "last_seen_at": user_session.last_seen_at.isoformat(),
        "is_current": (
            current_key is not None
            and user_session.session_key == current_key
        ),
    }


def prune_stale_sessions(user=None):
    """Drop inventory rows whose browser session no longer exists.

    Used by ``manage.py prune_expired``. Keeps the table from accumulating
    rows for sessions that expired naturally instead of being revoked.
    """
    queryset = UserSession.objects.filter(revoked_at__isnull=True)
    if user is not None:
        queryset = queryset.filter(user=user)

    removed = 0
    for row in queryset.iterator():
        if session_exists(row.session_key):
            continue
        row.revoked_at = timezone.now()
        row.save(update_fields=["revoked_at"])
        removed += 1

    return removed


def is_session_live(session_key):
    """True when Django still has data for this key."""
    return session_exists(session_key)


__all__ = [
    "active_sessions",
    "client_ip",
    "client_user_agent",
    "current_session_key",
    "destroy_session",
    "is_session_live",
    "prune_stale_sessions",
    "revoke_all_sessions",
    "revoke_other_sessions",
    "revoke_session",
    "revoke_session_by_key",
    "serialize_session",
    "session_exists",
    "session_user",
    "track_session",
]
