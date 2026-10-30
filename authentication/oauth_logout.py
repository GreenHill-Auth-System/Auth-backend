"""Single sign-out for the three relying parties.

The standard OpenID Connect RP-initiated logout endpoint lives at ``/o/logout/``
and django-oauth-toolkit already does the two things that matter most:

1. it ends the identity provider's session, so the browser stops being signed
   in here, and
2. with ``OIDC_RP_INITIATED_LOGOUT_DELETE_TOKENS`` it deletes every OAuth
   access and refresh token held for the account -- so signing out of PMS stops
   EID and ISMP working as well, rather than leaving them alive until their
   access token happens to expire.

What it does not do is retire the row this project keeps in ``UserSession``,
which is the inventory the account's "active sessions" screen reads from. Left
alone, a person who signs out from a relying party still sees that session
listed as active on the identity provider, with a device that is no longer
signed in.

This subclass closes that gap and then defers to the toolkit, so nothing about
the standard behaviour changes -- the same tokens are revoked, the same
``post_logout_redirect_uri`` validation applies, and the same redirect is
returned.
"""

from oauth2_provider.views import RPInitiatedLogoutView

from .sessions import revoke_session_by_key


class GreenHillRPInitiatedLogoutView(RPInitiatedLogoutView):
    """``/o/logout/`` plus the session inventory.

    ``/auth/logout/`` and ``/auth/logout-redirect/`` already do this through
    ``views._end_session``; this brings the standard OIDC endpoint in line with
    them, so a relying party that uses the standard route is not treated worse
    than one that uses this service's own.
    """

    def do_logout(
        self,
        application=None,
        post_logout_redirect_uri=None,
        state=None,
        token_user=None,
    ):
        # Read the key before calling the parent. It ends the session, which
        # flushes it and leaves ``session_key`` as ``None``.
        session_key = self.request.session.session_key

        if session_key:
            user = token_user or getattr(self.request, "user", None)

            if user is not None and getattr(user, "is_authenticated", False):
                revoke_session_by_key(session_key, user=user)
            else:
                # No trustworthy user to attribute the session to, but the key
                # still identifies a session this request is entitled to end.
                revoke_session_by_key(session_key)

        return super().do_logout(
            application=application,
            post_logout_redirect_uri=post_logout_redirect_uri,
            state=state,
            token_user=token_user,
        )
