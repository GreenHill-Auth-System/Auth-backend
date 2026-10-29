from oauth2_provider.oauth2_validators import OAuth2Validator


def _access_for(request):
    # Imported here to avoid a circular import at startup.
    from authentication.views import get_user_access

    return get_user_access(request.user.email)


class GreenHillOAuth2Validator(OAuth2Validator):
    oidc_claim_scope = dict(OAuth2Validator.oidc_claim_scope)

    oidc_claim_scope.update({
        "name": "profile",
        "given_name": "profile",
        "family_name": "profile",
        "preferred_username": "profile",
        "email": "email",
        "role": "profile",
        "authorized_systems": "profile",
    })

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
            "role": lambda request: _access_for(request)["role"],
            "authorized_systems": lambda request: _access_for(request)["authorized_systems"],
        }

    def get_discovery_claims(self, request):
        claims = super().get_discovery_claims(request)
        return list(set(claims) | {
            "email",
            "name",
            "given_name",
            "family_name",
            "preferred_username",
            "role",
            "authorized_systems",
        })