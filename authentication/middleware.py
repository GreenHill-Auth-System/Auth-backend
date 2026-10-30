"""Keeps the ``UserSession`` inventory in step with real browser sessions.

Django's ``SessionMiddleware`` and ``AuthenticationMiddleware`` already ran by
the time this executes, and the view has already handled ``login()`` /
``logout()``, so the session key written here is the final one.

Tracking runs *after* the response is produced. A failure to record a session
must never break the request that is being served, so every error is logged
and swallowed: the worst case is a missing row in the device list, not a 500.
"""

import logging

from authentication.sessions import track_session

logger = logging.getLogger(__name__)

# Paths that would otherwise create a session row for a request that cannot be
# part of a signed-in browsing experience.
SKIP_PREFIXES = (
    "/static/",
    "/admin/jsi18n/",
    "/favicon.ico",
)


class UserSessionMiddleware:
    """Refresh ``UserSession.last_seen_at`` at most once per interval."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        try:
            self._track(request)
        except Exception:  # pragma: no cover - defensive
            logger.exception("session tracking failed for %s", request.path)

        return response

    def _track(self, request):
        path = request.path
        if path.startswith(SKIP_PREFIXES):
            return

        # ``track_session`` resolves the account itself when ``request.user``
        # is anonymous, which is the case for DRF views that opt out of
        # authentication. Checking the session here avoids a database lookup
        # for genuinely anonymous traffic.
        if not request.session.get("_auth_user_id"):
            return

        track_session(request)
