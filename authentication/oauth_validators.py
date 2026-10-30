"""Django OAuth Toolkit validator for GreenHill.

Two responsibilities:

**Claims.**  The tokens and the ``userinfo`` endpoint carry the person's role
and the systems they may open, so a relying party never has to call back home
or keep its own copy of the access matrix.

**Scope enforcement.**  Without ``validate_scopes`` below, the toolkit only
checks that a *client* is allowed to request ``eid``. It does not check that
the *person* is. Any signed-in account could therefore request the ``eid``
scope and be issued a token carrying it, which would make the three systems'
own token checks meaningless. Every requested project scope is intersected
with what ``AllowedEmail`` actually grants.
"""

import logging

from oauth2_provider.oauth2_validators import OAuth2Validator

from authentication.access import get_user_access, split_requested_scopes

logger = logging.getLogger(__name__)


def _access_for(request):
    return get_user_access(request.user.email)


def _picture_url(request):
    """Absolute URL of this person's avatar, or ``""`` when they have none.

    Deliberately mirrors ``views._avatar_url`` rather than importing it: the
    view module pulls in every endpoint in the project, and this needs one
    string. Both read the same ``UserProfile`` row, so they cannot disagree
    about *whether* an avatar exists -- only about the unchanged URL shape.
    """
    profile = getattr(request.user, "greenhill_profile", None)

    if profile is None or not profile.has_avatar:
        return ""

    return request.build_absolute_uri(
        f"/auth/avatar/?v={int(profile.updated_at.timestamp())}"
    )


class GreenHillOAuth2Validator(OAuth2Validator):
    oidc_claim_scope = dict(OAuth2Validator.oidc_claim_scope)

    oidc_claim_scope.update({
        "name": "profile",
        "given_name": "profile",
        "family_name": "profile",
        "preferred_username": "profile",
        "email": "email",
        "picture": "profile",
        "role": "profile",
        "authorized_systems": "profile",
    })

    # ------------------------------------------------------------------
    # Scope enforcement
    # ------------------------------------------------------------------

    def validate_scopes(
        self,
        client_id,
        scopes,
        client,
        request,
        *args,
        **kwargs,
    ):
        """Reject a scope the client may not request *or* the user may not hold.

        ``super()`` already checks the client's allowed scopes. On top of that,
        a project scope (``eid``, ``procurement``, ``incident``) is only
        granted when the signed-in person has that system in
        ``AllowedEmail.authorized_systems``.

        The user check is skipped when the request is not authenticated. That
        is the token-exchange step of the authorisation-code flow, where the
        grant was already authorised -- and therefore already scope-checked --
        at ``/o/authorize/``. Re-checking with an anonymous user there would
        break the flow for everybody.
        """
        if not super().validate_scopes(
            client_id, scopes, client, request, *args, **kwargs
        ):
            return False

        user = getattr(request, "user", None)
        if user is None or not user.is_authenticated:
            return True

        allowed, denied = split_requested_scopes(user.email, scopes)

        if denied:
            logger.warning(
                "refused scopes %s for %s (allowed: %s)",
                sorted(denied),
                user.email or user.get_username(),
                sorted(allowed),
            )
            return False

        return True

    # ------------------------------------------------------------------
    # Claims
    # ------------------------------------------------------------------

    def get_additional_claims(self):
        return {
            "name": lambda request: " ".join(
                part for part in (
                    request.user.first_name,
                    request.user.last_name,
                ) if part
            ),
            "given_name": lambda request: request.user.first_name,
            "family_name": lambda request: request.user.last_name,
            "preferred_username": lambda request: request.user.username,
            "email": lambda request: request.user.email,
            "picture": _picture_url,
            "role": lambda request: _access_for(request)["role"],
            "authorized_systems": lambda request: _access_for(request)[
                "authorized_systems"
            ],
        }

    def get_discovery_claims(self, request):
        claims = super().get_discovery_claims(request)
        return list(set(claims) | {
            "email",
            "name",
            "given_name",
            "family_name",
            "preferred_username",
            "picture",
            "role",
            "authorized_systems",
        })