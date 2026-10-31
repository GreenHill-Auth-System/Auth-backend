"""Durable storage for the Google sign-in handshake state.

## The problem this solves

The OAuth 2.0 authorisation-code flow needs two values to survive the trip
through Google and come back to ``/auth/google/callback/``:

* ``state``      -- proves the callback belongs to a sign-in this browser
                    actually started, and not one an attacker composed;
* ``code_verifier`` -- the PKCE secret that proves the same client that
                    began the exchange is the one finishing it.

They used to live only in the Django session. That is correct on paper, but
the session cookie is issued on the backend host and then has to be presented
again after a **third-party redirect chain**
(our backend -> accounts.google.com -> our backend). Browsers are
increasingly hostile to exactly that pattern: a ``SameSite=None`` cookie is
subject to third-party storage limits, storage partitioning, and the user's
"block third-party cookies" setting. When the cookie is dropped, the callback
finds an empty session and the person sees "the sign-in was started in a
different browser" -- a message that blames them for a browser policy they
cannot see.

## The fix

The state is *also* carried in a cookie that:

* is scoped to ``/auth/google/callback/`` only, so it is never sent with any
  other request and cannot be read by another endpoint;
* is signed with ``SECRET_KEY``, so its contents are tamper-evident -- the
  browser can hold it but cannot forge a ``state`` or a ``code_verifier``;
* is ``SameSite=Lax``, which is what a top-level navigation from Google back to
  us needs, and is far more reliable than ``None`` in a redirect chain;
* expires in minutes.

The session copy is still written and still read first. This cookie is a
fallback for browsers that refuse to keep the session cookie, not a
replacement -- so behaviour on a browser that already works is unchanged.

Nothing here is trusted because it arrived in a cookie: the signature proves
we minted it, and the callback still compares the returned ``state`` against
the stored one.
"""

import logging

from django.conf import settings
from django.core import signing

logger = logging.getLogger(__name__)


#: Cookie name. Prefixed like the rest of the project's own cookies.
FLOW_COOKIE_NAME = "gh_google_flow"

#: Only the callback needs it, so only the callback receives it.
FLOW_COOKIE_PATH = "/auth/google/callback/"

#: Long enough for a slow account chooser, short enough to be useless later.
FLOW_COOKIE_MAX_AGE = 900  # 15 minutes

#: Namespace so a signature minted here cannot be replayed anywhere else.
_SALT = "authentication.google_flow"


def _signer():
    return signing.TimestampSigner(salt=_SALT)


def remember_flow(request, response, *, state, code_verifier):
    """Attach the signed handshake cookie to an outgoing redirect response."""
    payload = {"state": state, "code_verifier": code_verifier}

    response.set_cookie(
        FLOW_COOKIE_NAME,
        _signer().sign_object(payload),
        max_age=FLOW_COOKIE_MAX_AGE,
        path=FLOW_COOKIE_PATH,
        # `Lax` (not `None`) because the return leg is a top-level navigation.
        samesite="Lax",
        secure=settings.SESSION_COOKIE_SECURE,
        httponly=True,
    )
    return response


def read_flow(request):
    """Return ``(state, code_verifier)`` from the signed cookie, or ``(None, None)``.

    A forged, edited, or expired cookie is treated exactly like a missing one:
    the sign-in is refused. That is the point of signing it.
    """
    raw = request.COOKIES.get(FLOW_COOKIE_NAME)
    if not raw:
        return None, None

    try:
        payload = _signer().unsign_object(raw, max_age=FLOW_COOKIE_MAX_AGE)
    except signing.BadSignature as exc:
        logger.warning("google flow cookie rejected: %s", exc)
        return None, None
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("google flow cookie unreadable: %s", exc)
        return None, None

    if not isinstance(payload, dict):
        return None, None

    state = payload.get("state") or None
    verifier = payload.get("code_verifier") or None
    return state, verifier


def forget_flow(response):
    """Delete the handshake cookie. Safe to call when it was never set."""
    response.delete_cookie(
        FLOW_COOKIE_NAME,
        path=FLOW_COOKIE_PATH,
        samesite="Lax",
    )
    return response
