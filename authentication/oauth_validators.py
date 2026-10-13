
from oauth2_provider.oauth2_validators import OAuth2Validator


class GreenHillOAuth2Validator(OAuth2Validator):
    # Copy the standard mapping so we don't modify the
    # base validator's shared dictionary.
    oidc_claim_scope = dict(OAuth2Validator.oidc_claim_scope)

    # Only release identity claims when the client has
    # requested the appropriate scopes.
    oidc_claim_scope.update({
        "name": "profile",
        "given_name": "profile",
        "family_name": "profile",
        "preferred_username": "profile",
        "email": "email",
    })

    def get_additional_claims(self):
        # Return callables so discovery can identify the
        # supported claims without requiring a logged-in user.
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
        }

    
    def get_discovery_claims(self, request):
        claims = super().get_discovery_claims(request)
        return list(set(claims) | {
            "email",
            "name",
            "given_name",
            "family_name",
            "preferred_username",
        })

