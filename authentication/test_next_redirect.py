"""Tests for the ``next`` round trip through sign-in.

When a relying party sends a browser to ``/o/authorize/`` without a session,
the toolkit redirects to the IdP login page with the full authorize URL in
``next``. That URL has to survive the trip out to Google and back, otherwise
SSO degrades into "sign in, then land on the dashboard and click the app
again".

``next`` is attacker-controlled, so the unsafe cases matter just as much as
the happy path.
"""

from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase

from .views import (
    DEFAULT_LANDING_PATH,
    POST_LOGIN_REDIRECT_KEY,
    _is_safe_redirect,
    consume_post_login_redirect,
    get_frontend_url,
    remember_post_login_redirect,
)

User = get_user_model()


class SafeRedirectTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_relative_path_is_safe(self):
        request = self.factory.get("/auth/google/login/")
        self.assertTrue(_is_safe_redirect("/o/authorize/?client_id=x", request))

    def test_absolute_external_url_is_not_safe(self):
        request = self.factory.get("/auth/google/login/")
        self.assertFalse(_is_safe_redirect("https://evil.example/steal", request))

    def test_protocol_relative_url_is_not_safe(self):
        request = self.factory.get("/auth/google/login/")
        self.assertFalse(_is_safe_redirect("//evil.example/steal", request))

    def test_blank_is_not_safe(self):
        request = self.factory.get("/auth/google/login/")
        self.assertFalse(_is_safe_redirect("", request))
        self.assertFalse(_is_safe_redirect(None, request))

    def test_javascript_scheme_is_not_safe(self):
        request = self.factory.get("/auth/google/login/")
        self.assertFalse(_is_safe_redirect("javascript:alert(1)", request))

    def test_own_host_is_safe(self):
        request = self.factory.get("/auth/google/login/", HTTP_HOST="auth.example")
        self.assertTrue(_is_safe_redirect("https://auth.example/o/authorize/", request))


class RememberRedirectTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def _request(self, session_store, **params):
        request = self.factory.get("/auth/google/login/", params)
        request.session = session_store
        return request

    def test_safe_target_is_stored(self):
        store = {}
        request = self._request(store, next="/o/authorize/?client_id=x")
        self.assertEqual(remember_post_login_redirect(request), "/o/authorize/?client_id=x")
        self.assertEqual(store[POST_LOGIN_REDIRECT_KEY], "/o/authorize/?client_id=x")

    def test_external_target_is_dropped(self):
        store = {}
        request = self._request(store, next="https://evil.example/")
        self.assertEqual(remember_post_login_redirect(request), "")
        self.assertNotIn(POST_LOGIN_REDIRECT_KEY, store)

    def test_missing_target_is_a_no_op(self):
        store = {}
        request = self._request(store)
        self.assertEqual(remember_post_login_redirect(request), "")
        self.assertEqual(store, {})


class ConsumeRedirectTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def _request(self, session_store):
        request = self.factory.get("/auth/google/callback/")
        request.session = session_store
        return request

    def test_stored_target_is_returned_once(self):
        store = {POST_LOGIN_REDIRECT_KEY: "/o/authorize/?client_id=x"}
        request = self._request(store)
        self.assertEqual(consume_post_login_redirect(request), "/o/authorize/?client_id=x")
        self.assertNotIn(POST_LOGIN_REDIRECT_KEY, store)

    def test_default_landing_page_when_nothing_was_stored(self):
        request = self._request({})
        self.assertEqual(
            consume_post_login_redirect(request),
            f"{get_frontend_url()}{DEFAULT_LANDING_PATH}",
        )

    def test_frontend_url_has_no_trailing_slash(self):
        self.assertFalse(get_frontend_url().endswith("/"))


class SessionUserTests(TestCase):
    def test_helper_reads_the_session_not_the_request_user(self):
        from .views import _session_user

        user = User.objects.create_user(
            username="cnmusisi@greenhillacademy.ac.ug",
            email="cnmusisi@greenhillacademy.ac.ug",
            password="pw-for-tests-123",
        )
        request = SimpleNamespace(session={"_auth_user_id": str(user.pk)})
        self.assertEqual(_session_user(request), user)

    def test_absent_or_broken_ids_return_none(self):
        from .views import _session_user

        self.assertIsNone(_session_user(SimpleNamespace(session={})))
        self.assertIsNone(_session_user(SimpleNamespace(session={"_auth_user_id": "nope"})))
