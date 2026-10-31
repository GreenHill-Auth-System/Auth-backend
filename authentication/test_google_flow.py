"""Tests for the durable Google handshake state.

These cover the failure that produced "the sign-in took too long or was started
in a different browser" for a person who had done nothing wrong: the browser
dropped the session cookie on the way back from Google, so the callback found
an empty session and refused the sign-in.

The contract under test:

* a normal session-based flow still works and is still preferred;
* when the session cookie is missing but the signed handshake cookie survives,
  the sign-in continues instead of failing;
* a forged or edited handshake cookie is refused -- falling back must never
  weaken the CSRF protection that ``state`` exists for;
* the cookie is scoped to the callback path and cleared after use.
"""

from django.test import TestCase
from django.urls import reverse

from authentication.google_flow import (
    FLOW_COOKIE_NAME,
    FLOW_COOKIE_PATH,
    forget_flow,
    read_flow,
    remember_flow,
)


class RememberFlowTests(TestCase):
    def _response_with_flow(self):
        from django.http import HttpResponse

        response = HttpResponse()
        return remember_flow(
            None,
            response,
            state="state-value-123",
            code_verifier="verifier-value-456",
        )

    def test_cookie_is_written(self):
        response = self._response_with_flow()

        self.assertIn(FLOW_COOKIE_NAME, response.cookies)

    def test_cookie_is_scoped_to_the_callback(self):
        response = self._response_with_flow()

        self.assertEqual(response.cookies[FLOW_COOKIE_NAME]["path"], FLOW_COOKIE_PATH)

    def test_cookie_is_httponly_and_lax(self):
        response = self._response_with_flow()
        cookie = response.cookies[FLOW_COOKIE_NAME]

        self.assertTrue(cookie["httponly"])
        # `Lax`, not `None`: the return leg from Google is a top-level
        # navigation, and `None` is the value browsers drop.
        self.assertEqual(cookie["samesite"], "Lax")

    def test_cookie_expires_quickly(self):
        response = self._response_with_flow()

        self.assertLessEqual(response.cookies[FLOW_COOKIE_NAME]["max-age"], 900)


class ReadFlowTests(TestCase):
    def _request_with_cookie(self, value):
        from django.test import RequestFactory

        request = RequestFactory().get("/auth/google/callback/")
        request.COOKIES[FLOW_COOKIE_NAME] = value
        return request

    def _signed_value(self):
        response = remember_flow(
            None,
            __import__("django.http", fromlist=["HttpResponse"]).HttpResponse(),
            state="state-value-123",
            code_verifier="verifier-value-456",
        )
        return response.cookies[FLOW_COOKIE_NAME].value

    def test_round_trips_the_handshake(self):
        state, verifier = read_flow(self._request_with_cookie(self._signed_value()))

        self.assertEqual(state, "state-value-123")
        self.assertEqual(verifier, "verifier-value-456")

    def test_missing_cookie_returns_nothing(self):
        from django.test import RequestFactory

        request = RequestFactory().get("/auth/google/callback/")

        self.assertEqual(read_flow(request), (None, None))

    def test_tampered_cookie_returns_nothing(self):
        value = self._signed_value()
        tampered = value[:-4] + "AAAA"

        self.assertEqual(read_flow(self._request_with_cookie(tampered)), (None, None))

    def test_forged_cookie_returns_nothing(self):
        import base64
        import json

        forged = base64.urlsafe_b64encode(
            json.dumps(
                {"state": "attacker-state", "code_verifier": "attacker-verifier"}
            ).encode()
        ).decode().rstrip("=")

        self.assertEqual(read_flow(self._request_with_cookie(forged)), (None, None))

    def test_cookie_signed_for_another_purpose_is_refused(self):
        from django.core import signing

        foreign = signing.TimestampSigner(salt="somewhere.else").sign_object(
            {"state": "other-state", "code_verifier": "other-verifier"}
        )

        self.assertEqual(read_flow(self._request_with_cookie(foreign)), (None, None))


class ForgetFlowTests(TestCase):
    def test_cookie_is_deleted_on_the_callback_path(self):
        from django.http import HttpResponse

        response = forget_flow(HttpResponse())
        cookie = response.cookies[FLOW_COOKIE_NAME]

        self.assertEqual(cookie["path"], FLOW_COOKIE_PATH)
        self.assertEqual(cookie["max-age"], 0)

    def test_safe_to_call_when_no_cookie_was_set(self):
        from django.http import HttpResponse

        self.assertIsNotNone(forget_flow(HttpResponse()))


class CallbackRecoveryTests(TestCase):
    """The callback must recover when only the signed cookie survived.

    A "did the state check pass?" answer is read off *which* error code comes
    back: ``oauth_state_missing`` means the handshake was rejected, while
    ``oauth_token_exchange_failed`` means it was accepted and the flow got as
    far as talking to Google. The token exchange is stubbed to fail so the test
    never reaches the network.
    """

    def _flow_cookie(self):
        from django.http import HttpResponse

        response = remember_flow(
            None,
            HttpResponse(),
            state="cookie-state",
            code_verifier="cookie-verifier",
        )
        return response.cookies[FLOW_COOKIE_NAME].value

    def test_callback_uses_signed_cookie_when_session_is_empty(self):
        from unittest.mock import patch

        self.client.cookies[FLOW_COOKIE_NAME] = self._flow_cookie()

        with patch.object(
            __import__(
                "google_auth_oauthlib.flow", fromlist=["Flow"]
            ).Flow,
            "fetch_token",
            side_effect=RuntimeError("stubbed"),
        ):
            response = self.client.get(
                reverse("google_callback"),
                {"state": "cookie-state", "code": "any-code"},
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn("error=oauth_token_exchange_failed", response.url)

    def test_callback_still_rejects_a_mismatched_state_from_the_cookie(self):
        self.client.cookies[FLOW_COOKIE_NAME] = self._flow_cookie()

        response = self.client.get(
            reverse("google_callback"),
            {"state": "attacker-state", "code": "any-code"},
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("error=oauth_state_missing", response.url)

    def test_callback_prefers_the_session_when_both_exist(self):
        session = self.client.session
        session["google_oauth_state"] = "session-state"
        session["google_code_verifier"] = "session-verifier"
        session.save()
        self.client.cookies[FLOW_COOKIE_NAME] = self._flow_cookie()

        response = self.client.get(
            reverse("google_callback"),
            {"state": "cookie-state", "code": "any-code"},
        )

        # The session's state wins, so the cookie's state is a mismatch.
        self.assertIn("error=oauth_state_missing", response.url)

    def test_handshake_cookie_is_cleared_after_use(self):
        from unittest.mock import patch

        self.client.cookies[FLOW_COOKIE_NAME] = self._flow_cookie()

        with patch.object(
            __import__(
                "google_auth_oauthlib.flow", fromlist=["Flow"]
            ).Flow,
            "fetch_token",
            side_effect=RuntimeError("stubbed"),
        ):
            response = self.client.get(
                reverse("google_callback"),
                {"state": "cookie-state", "code": "any-code"},
            )

        self.assertEqual(response.cookies[FLOW_COOKIE_NAME]["max-age"], 0)
