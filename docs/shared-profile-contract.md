# One profile, three systems

EID, PMS and ISMP all sign people in through this auth backend. Each of them
currently keeps its **own copy** of the person -- a local user row, or a
hardcoded placeholder -- and serves that copy to its own UI. Copies drift. That
is why one login can show a different name or photo in each system.

This document is the contract. The auth backend is the single source of truth;
each system renders what it is given and never invents its own version.

---

## 1. The contract

### `GET /auth/me/` (cookie session, JSON)

```json
{
  "authenticated": true,
  "user": {
    "email": "ada@greenhillacademy.ac.ug",
    "name": "Ada Lovelace",
    "first_name": "Ada",
    "last_name": "Lovelace",
    "role": "CEO",
    "authorized_systems": ["EID", "PMS"],
    "picture": "https://greenhill-auth-backend2.onrender.com/auth/avatar/?v=17&t=...",
    "profile_version": 1793432889123
  }
}
```

When nobody is signed in the answer is `401` with `{"authenticated": false}`.

Guarantees:

| Field | Guarantee |
| --- | --- |
| `name` | Never empty. Falls back to `first_name`, then to `email`. |
| `email` | Lower-cased, and the key access is granted by. Never editable. |
| `role` | Recalculated from the access policy on **every** call, not from the session. |
| `authorized_systems` | Same. Drives which systems this person may enter. |
| `picture` | **Absent** when the person has no photo. Do not assume it exists. |
| `profile_version` | Changes when anything displayed about the person changes. Opaque integer. |

### `/auth/avatar/?v=…&t=…`

The `picture` URL carries its own signed token, valid 24 hours. **It loads with
no cookie.** This matters: `onrender.com` is a public suffix, so
`greenhill-eid-frontend.onrender.com` and `greenhill-auth-backend2.onrender.com`
are different *sites*, not just different origins. An `<img>` on the EID page is
a third-party request there, and the session cookie is not sent.

Consequence: render `picture` as a plain `<img src>`. Do **not** fetch it with
`credentials: "include"`, and do not try to hit `/auth/avatar/` without the
token from the identity response.

### OIDC (for backend-to-backend logins)

The same fields are in the ID token / `/o/userinfo/`:

```
sub, email, email_verified, name, given_name, family_name,
preferred_username, picture, role, authorized_systems, profile_version
```

`role`, `authorized_systems`, `picture` and `profile_version` require the
`profile` scope, which every client already requests.

---

## 2. Auth backend (done)

Nothing to do. `profile_version` is on `/auth/me/`, on `/auth/profile/` and in
the claims; it moves on every profile write including a rename.

---

## 3. EID backend — `EXECUTIVE-INTELLIGENCE-DASHBOARD/Backend`

Repo layout: `core/oidc_views.py`, `core/urls.py`. Mounted under `/api/`.

### 3a. Stop discarding the identity at the callback

`core/oidc_views.py`, in `greenhill_callback`, after
`userinfo` has been validated. Right now the response only copies
`email`, `given_name`, `family_name` into a local user row and throws the rest
away:

```python
# Keep the identity the auth backend gave us. The local user row stays,
# because EID owns its own permissions and foreign keys, but it is no
# longer the source of the displayed profile.
request.session["greenhill_profile"] = {
    "sub": userinfo["sub"],
    "email": userinfo["email"],
    "name": userinfo["name"],
    "first_name": userinfo.get("given_name", ""),
    "last_name": userinfo.get("family_name", ""),
    "role": userinfo.get("role"),
    "authorized_systems": userinfo.get("authorized_systems", []),
    "picture": userinfo.get("picture", ""),
    "profile_version": userinfo.get("profile_version", 0),
}
request.session["greenhill_token"] = token
```

`token` is what `authorize_access_token` already returned; keep it so the
profile can be refreshed in 3c.

Also prefer `sub` over the email to identify the local row. Today the code does
`username = f"gh_{subject}"` and then matches on email elsewhere -- if someone's
Google address changes, they get a second local user and lose their history.
Store `sub` on the user row (one small `CharField`, unique, nullable) and match
on that.

### 3b. Serve the real profile

Replace the body of `current_user` so it reports the contract shape:

```python
profile = request.session.get("greenhill_profile") or {}
return JsonResponse({
    "authenticated": True,
    "user": {
        "email": profile.get("email", user.email),
        "name": profile.get("name") or user.get_full_name() or user.email,
        "first_name": profile.get("first_name", user.first_name),
        "last_name": profile.get("last_name", user.last_name),
        "role": profile.get("role"),
        "authorized_systems": profile.get("authorized_systems", []),
        "picture": profile.get("picture", ""),
        "profile_version": profile.get("profile_version", 0),
    },
})
```

### 3c. Refresh when the version moves (10 lines)

A name changed in the profile page should appear without a re-login. authlib
refreshes the token for you when the stored token carries a refresh token:

```python
def _refresh_profile(request):
    token = request.session.get("greenhill_token")
    if not token:
        return
    try:
        fresh = oauth.greenhill.get("userinfo", token=token)
    except Exception:
        return  # offline, revoked, expired beyond refresh: keep the old copy
    if not fresh:
        return
    profile = request.session.get("greenhill_profile") or {}
    if fresh.get("profile_version") == profile.get("profile_version"):
        return  # unchanged, nothing to write
    profile.update({
        "name": fresh.get("name"),
        "first_name": fresh.get("given_name", ""),
        "last_name": fresh.get("family_name", ""),
        "role": fresh.get("role"),
        "authorized_systems": fresh.get("authorized_systems", []),
        "picture": fresh.get("picture", ""),
        "profile_version": fresh.get("profile_version", 0),
    })
    request.session["greenhill_profile"] = profile
    request.session["greenhill_token"] = token
```

Call it at the top of `current_user`. It costs one HTTP request when the
version has moved and stops at the session otherwise.

### 3d. Log out everywhere, not just here

`greenhill_logout` currently drops EID's own cookie and returns. The auth
backend session and its OAuth tokens stay alive, so the next EID visit silently
signs the person straight back in. After `django_logout(request)`, also tell the
auth backend:

```python
import requests
try:
    requests.post(f"{settings.GREENHILL_ISSUER}/auth/logout/",
                  cookies={"sessionid": request.COOKIES.get("sessionid")},
                  timeout=5)
except requests.RequestException:
    pass  # local sign-out already happened; do not fail the request
```

(Or the simpler, more reliable variant: redirect the browser to the auth
backend's `/auth/logout-redirect/?next=<frontend>/` and let it end the session
and come back.)

---

## 4. EID frontend — `EXECUTIVE-INTELLIGENCE-DASHBOARD/Frontend`

### 4a. Let the type carry the fields

`src/lib/api/types.ts` currently drops them:

```ts
export interface AuthUser {
  id?: number;
  email: string;
  name: string;
  first_name: string;
  last_name: string;
  role?: string;
  authorized_systems?: string[];
  picture?: string;
  profile_version?: number;
}
```

### 4b. Delete the hardcoded header

`src/lib/userProfile.ts` is the actual bug:

```ts
export const userProfile: UserProfile = { name: "Greenhill Academy", initials: "GA" };
```

Every signed-in user sees "Greenhill Academy" / "GA". Delete the file and have
the component read the session instead.

### 4c. Render the session in `src/components/Hero.tsx`

It already imports `userProfile` (line 5) but never calls `useSession()`, which
exists in `src/lib/api/queries.ts`. Replace the constant with:

```tsx
import { useSession } from "../lib/api/queries";

const { data: user } = useSession();

const initials = [user?.first_name, user?.last_name]
  .filter(Boolean)
  .map((part) => part![0])
  .join("")
  .slice(0, 2)
  .toUpperCase();

const displayName = user?.name?.trim() || user?.email || "Greenhill Academy";
```

and in the markup:

```tsx
<span className="hero__avatar">
  {user?.picture ? (
    <img src={user.picture} alt="" width={40} height={40} />
  ) : (
    initials || "GA"
  )}
</span>
<span className="hero__user-name">{displayName}</span>
```

`user.picture` is a signed URL: plain `<img src>`, no `fetch`, no credentials.
Update `Hero.test.tsx` to mock `useSession` instead of the deleted constant.

### 4d. Any other placeholder header

Search for `"Greenhill Academy"` and `"GA"` in `src/` -- the same constant may be
imported in the layout shell or a sidebar. Every signed-in header must render
`useSession()`.

---

## 5. PMS and ISMP

Same three rules, adapted to their stack:

1. **One identity call.** `GET /auth/me/` (or the OIDC userinfo endpoint) on
   load. If they have a local user table, keep it for their own permissions and
   foreign keys, but never for the name or photo shown to the user.
2. **Avatar from `picture`.** Render it as a plain `<img src>`. It needs no
   cookie and works cross-site.
3. **Log out through the auth backend.** `/auth/logout/` or
   `/auth/logout-redirect/`. A local-cookie-only logout leaves the SSO session
   alive and signs the person back in on the next click.
4. **No placeholders.** Any hardcoded name, initials or logo standing in for the
   signed-in user is the same bug as EID's `userProfile.ts`.

Their repos are `pms-frontend-4fm8.onrender.com` and
`165.232.50.141.sslip.io`. The local folders still need confirming before anyone
edits them.

---

## 6. Signing out from any system

A "Sign out" button in EID, PMS or ISMP must end the single sign-on session, kill
the OAuth tokens, and leave the person on a sign-in page so the next login mints
a fresh token. Otherwise the relying party keeps a working access token after the
user believes they have left.

**Status.** Verified working in the auth app and in EID: both clear their own
session, then navigate the browser to `/auth/logout-redirect/`, which ends the
SSO session and deletes every token for the account. PMS and ISMP are not
verified — same pattern applies, see below.

### The one rule

**Navigate the browser; do not `fetch`.** The three systems are on sibling
`*.onrender.com` hosts and that suffix is a public suffix, so a `fetch` from one
of their pages is a third-party request and the shared session cookie is
routinely withheld. A top-level navigation *is* sent the cookie.

```
https://greenhill-auth-backend2.onrender.com/auth/logout-redirect/?next=<where-to-land>
```

That endpoint ends the session, revokes every access and refresh token for the
account, and 302s to `next`. `next` must be an absolute URL on a trusted origin:
this service's frontend, an origin in `CORS_ALLOWED_ORIGINS`, or a relying
party's registered `post_logout_redirect_uris`. Anything else is dropped and the
browser lands on the auth frontend.

### The button

```tsx
const SSO = import.meta.env.VITE_SSO_BASE_URL; // auth backend origin

function signOutEverywhere() {
  // Local session first: it is what this system's own API trusts. Then hand
  // the browser to the auth backend, which ends the SSO session and returns
  // the user to a sign-in page.
  fetch("/api/auth/logout/", { method: "POST", credentials: "include" })
    .catch(() => {})
    .finally(() => {
      window.location.assign(
        `${SSO}/auth/logout-redirect/?next=${encodeURIComponent(window.location.origin + "/")}`
      );
    });
}
```

If the system has no local logout endpoint, drop the `fetch` and just navigate.

### Server side, when you have a token

A backend holding an access token can revoke it directly, with no cookie and no
browser:

```bash
curl -X POST https://greenhill-auth-backend2.onrender.com/auth/logout/ \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

```json
{
  "authenticated": false,
  "message": "You have been signed out successfully.",
  "sessions_revoked": 1,
  "access_tokens_revoked": 1,
  "refresh_tokens_revoked": 1,
  "redirect_to": "https://greenhill-auth-frontend2.onrender.com/"
}
```

`redirect_to` is where a JSON caller should send the browser. It honours a
`next` passed in the body, under the same trust rules.

Only a **live** token identifies anyone: an expired or unknown bearer value
revokes nothing, and an inactive account revokes nothing. When both a session
cookie and a bearer token are present the cookie wins, because that is the
browser's own sign-out.

| Endpoint | Ends | Revokes | Method |
| --- | --- | --- | --- |
| `/auth/logout/` | this session | all tokens for the account | `POST` |
| `/auth/logout-everywhere/` | every session | all tokens for the account | `POST` |
| `/auth/logout-redirect/?next=` | this session | all tokens for the account | `GET` (navigation) |

Note the middle column: sign-out is global by design. A person who signs out of
EID is signed out of PMS and ISMP too, and has to log in again — which is the
behaviour requested, and the only version that cannot leave a live token behind
in a system nobody remembered to tidy.

### What each system must also do

* **Clear its own session.** The auth backend cannot delete EID's Django session
  or PMS's cookie. Do that in the system's own `/logout/`, in the same click.
* **Do not cache the token.** After sign-out every API call must be prepared to
  get `401` and show the sign-in page rather than an empty shell.
* **Do not reuse the old token.** A revoked token is deleted, so presenting it
  returns `401 invalid_token`, not a stale success.

### The back arrow is a sign-in unless you close it

Signing out is only half the job. A browser is allowed to keep the page you left
in memory — the back/forward cache — and put it back on the glass with no
network request at all: React does not mount, no effect runs, and the dashboard
you signed out of is simply returned. To a person that looks exactly like
"the back arrow logs me in".

Three things have to be true in every system. One of them is a server change,
which is why it belongs in this document.

**1. The server must say the answer is not reusable.**

```http
Cache-Control: no-store, no-cache, must-revalidate, private, max-age=0
Pragma: no-cache
Expires: 0
```

on every response that talks about a session: `/auth/me/`, the profile, the
settings, the session list, the sign-out result. The auth backend does this with
`authentication/cache_headers.py`; EID's `core/oidc_views.py` does it per view.
Without it a `200 {"authenticated": true}` can be replayed from the cache after
the person has left.

**2. No answer about the session may be read from the cache.**

```ts
await fetch("/api/auth/me/", {
  credentials: "include",
  cache: "no-store",           // not optional
  headers: { Accept: "application/json" },
});
```

**3. The shell must be hidden until the server answers.** Not redirected, not
"show the dashboard and fix it when the data fails" — hidden. A dashboard whose
panels are empty still tells the person which pages exist, and every click is a
request made with no session behind it. Gate the whole layout, and re-ask the
question on the three ways a signed-out screen comes back:

| Event | When | What to do |
| --- | --- | --- |
| `pageshow` with `persisted` | the back/forward cache restored the page | hide first, then ask |
| `popstate` | an in-app history move | ask |
| `visibilitychange` → `visible` | tab regains focus after sign-out elsewhere | ask |

EID implements this in `src/components/SessionGate.tsx` and
`src/lib/session.ts`; the auth app does it inline in `src/App.tsx`. Copy either.

Two details that are easy to get wrong:

* **`unknown` is not `signed-out`.** A 502 from a cold instance says nothing
  about the person's credentials. Close the gate on two definite `no` answers,
  never on a timeout.
* **A sign-in link must start a sign-in.** Link to `<backend>/api/auth/login/`,
  not to a `/login` route that may not exist and not to the provider's front
  page, which only shows the workspace list and loops back.

---

## 7. How to prove it works


1. Sign in to the auth app as a test user; set a first and last name and upload
   an avatar.
2. Sign in to EID, PMS and ISMP **as the same person**. All three headers must
   show the same name and the same photo.
3. Change the name in the auth app's profile page. Reload each system. All three
   must show the new name (EID: after 3c returns a new `profile_version`).
4. Sign out in one system; the others must not let you back in without a fresh
   password.
5. Before signing in again, replay the old access token against `/o/userinfo/`.
   It must answer `401`. After signing in again, the new token must be a
   different value — that is the proof that a new token is issued per login.

