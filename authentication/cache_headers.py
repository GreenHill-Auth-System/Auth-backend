"""Cache headers for everything this service answers about a person.

The back and forward arrows are the browser's memory, not the server's. A
restored page does not ask again: if the last answer it saw is still in the
cache, that answer is what the user gets, credentials or not. So any cacheable
response from this service is a way back in after a sign-out.

The auth frontend already passes ``cache: "no-store"`` on its one identity
fetch. The three systems do not -- a system using axios sends no cache
directive at all, which leaves the browser free to reuse the last ``200`` from
``/auth/me/`` when the page is restored. That is the difference between "signed
out" and "looks signed out but navigates the old shell".

Defending here rather than asking three teams to remember a flag is the point:
the header ships with the answer, so it cannot be forgotten by a caller.

The avatar is the one exception. It is a picture, not a claim about who is
signed in, it is already marked ``private, max-age=300`` by its own view, and
re-downloading it on every render is the only thing that flag prevents.
"""

from django.utils.cache import patch_vary_headers

# Prefixes whose answers describe a person or a session. `/auth/avatar/` is the
# single carve-out, handled below.
PROTECTED_PREFIXES = (
    "/auth/",
    "/o/userinfo/",
    "/o/introspect/",
)

# Answers that are files rather than statements about a session policy.
EXEMPT_PREFIXES = ("/auth/avatar/",)

# `no-store` forbids writing the response to disk at all, which is what stops
# the forward arrow restoring a signed-in answer. The rest is belt and braces
# for older caches that honour `Pragma`/`Expires` but not `no-store`.
NO_STORE = "no-store, no-cache, must-revalidate, private, max-age=0"


class NoStoreAuthResponses:
    """Mark every identity/authorization answer uncacheable.

    ``Vary: Cookie`` matters as much as ``no-store``: without it a shared cache
    that ignores `no-store` could still hand one user's answer to another.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        path = request.path_info or ""

        if any(path.startswith(prefix) for prefix in EXEMPT_PREFIXES):
            return response

        if not any(path.startswith(prefix) for prefix in PROTECTED_PREFIXES):
            return response

        response["Cache-Control"] = NO_STORE
        response["Pragma"] = "no-cache"
        response["Expires"] = "0"
        patch_vary_headers(response, ("Cookie",))

        return response
