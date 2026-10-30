"""Tests for the session manager: inventory, listing and revocation.

These cover the behaviour the "where am I signed in?" screen depends on, plus
the parts that are easy to get subtly wrong: the current session must not be
revoked by "sign out other devices", revoking must actually delete the Django
session row rather than only flagging it, and tracking must not fire on every
single request.
"""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.test import TestCase
from django.test.utils import override_settings
from django.utils import timezone

from .models import UserSession
from .sessions import (
    active_sessions,
    client_ip,
    current_session_key,
    is_session_live,
    prune_stale_sessions,
    revoke_all_sessions,
    revoke_other_sessions,
    revoke_session,
    revoke_session_by_key,
    serialize_session,
    track_session,
)

User = get_user_model()


def make_user(email="cnmusisi@greenhillacademy.ac.ug", password="pw-for-tests-123"):
    return User.objects.create_user(username=email, email=email, password=password)


def store_session(session_key):
    """Persist a Django session row so it can be found and destroyed."""
    session, _ = Session.objects.get_or_create(
        session_key=session_key,
        defaults={
            "session_data": "",
            "expire_date": timezone.now() + timedelta(days=365),
        },
    )
    return session


class UserSessionModelTests(TestCase):
    def test_is_active_tracks_revoked_at(self):
        user = make_user()
        row = UserSession.objects.create(user=user, session_key="key-1")
        self.assertTrue(row.is_active)

    def test_str_mentions_user(self):
        user = make_user()
        row = UserSession.objects.create(user=user, session_key="key-1")
        self.assertIn(user.email, str(row))


class ClientIpTests(TestCase):
    def test_x_forwarded_for_first_entry_wins(self):
        request = type("R", (), {"META": {"HTTP_X_FORWARDED_FOR": "1.2.3.4, 10.0.0.1"}})()
        self.assertEqual(client_ip(request), "1.2.3.4")

    def test_falls_back_to_remote_addr(self):
        request = type("R", (), {"META": {"REMOTE_ADDR": "5.6.7.8"}})()
        self.assertEqual(client_ip(request), "5.6.7.8")

    def test_none_when_nothing_known(self):
        request = type("R", (), {"META": {}})()
        self.assertIsNone(client_ip(request))


class TrackSessionTests(TestCase):
    def setUp(self):
        self.user = make_user()

    def _request(self, key="session-abc", user_agent="pytest", ip="1.2.3.4"):
        session = type("S", (), {"session_key": key})()
        return type(
            "R",
            (),
            {
                "user": self.user,
                "session": session,
                "META": {
                    "HTTP_USER_AGENT": user_agent,
                    "REMOTE_ADDR": ip,
                },
            },
        )()

    def test_creates_a_row(self):
        row = track_session(self._request(), self.user, force=True)
        self.assertIsNotNone(row)
        self.assertEqual(row.session_key, "session-abc")
        self.assertEqual(row.ip_address, "1.2.3.4")
        self.assertEqual(row.user_agent, "pytest")

    def test_anonymous_requests_are_not_tracked(self):
        anonymous = type("U", (), {"is_authenticated": False})()
        request = self._request()
        request.user = anonymous
        self.assertIsNone(track_session(request, anonymous))
        self.assertEqual(UserSession.objects.count(), 0)

    def test_missing_session_key_is_not_tracked(self):
        self.assertIsNone(track_session(self._request(key=None), self.user))

    def test_second_call_inside_the_interval_is_a_no_op(self):
        self.assertIsNotNone(track_session(self._request(), self.user, force=True))
        self.assertIsNone(track_session(self._request(), self.user))
        self.assertEqual(UserSession.objects.count(), 1)

    @override_settings(SESSION_TOUCH_INTERVAL=0)
    def test_touching_updates_last_seen(self):
        first = track_session(self._request(), self.user, force=True)
        first_stamp = first.last_seen_at
        second = track_session(self._request(ip="9.9.9.9"), self.user)
        self.assertIsNotNone(second)
        self.assertGreaterEqual(second.last_seen_at, first_stamp)
        self.assertEqual(second.ip_address, "9.9.9.9")

    def test_revoked_row_is_revived_when_seen_again(self):
        row = track_session(self._request(), self.user, force=True)
        row.revoked_at = row.created_at
        row.save(update_fields=["revoked_at"])

        revived = track_session(self._request(), self.user, force=True)
        self.assertIsNone(revived.revoked_at)


class RevokeTests(TestCase):
    def setUp(self):
        self.user = make_user()

    def test_revoke_session_deletes_the_django_session(self):
        row = UserSession.objects.create(user=self.user, session_key="key-1")
        store_session("key-1")
        self.assertTrue(is_session_live("key-1"))

        self.assertTrue(revoke_session(row))
        self.assertFalse(is_session_live("key-1"))
        row.refresh_from_db()
        self.assertIsNotNone(row.revoked_at)

    def test_revoke_session_by_key_without_inventory_row_still_deletes(self):
        store_session("orphan-key")
        self.assertTrue(revoke_session_by_key("orphan-key"))
        self.assertFalse(is_session_live("orphan-key"))

    def test_revoke_session_by_key_ignores_a_foreign_user(self):
        other = make_user("other@greenhillacademy.ac.ug")
        UserSession.objects.create(user=other, session_key="key-1")
        store_session("key-1")

        self.assertFalse(revoke_session_by_key("key-1", user=self.user))
        self.assertTrue(is_session_live("key-1"))

    def test_revoke_session_by_key_with_blank_key(self):
        self.assertFalse(revoke_session_by_key(None))

    def test_revoke_other_sessions_keeps_the_current_one(self):
        for key in ("keep", "drop-1", "drop-2"):
            UserSession.objects.create(user=self.user, session_key=key)
            store_session(key)

        revoked = revoke_other_sessions(self.user, keep_session_key="keep")

        self.assertEqual(revoked, 2)
        self.assertTrue(is_session_live("keep"))
        self.assertFalse(is_session_live("drop-1"))
        self.assertFalse(is_session_live("drop-2"))
        self.assertEqual(active_sessions(self.user).count(), 1)

    def test_revoke_all_sessions_hits_every_row(self):
        for key in ("a", "b"):
            UserSession.objects.create(user=self.user, session_key=key)
            store_session(key)

        self.assertEqual(revoke_all_sessions(self.user), 2)
        self.assertEqual(active_sessions(self.user).count(), 0)

    def test_revoke_all_leaves_other_accounts_alone(self):
        other = make_user("other@greenhillacademy.ac.ug")
        UserSession.objects.create(user=other, session_key="theirs")
        UserSession.objects.create(user=self.user, session_key="mine")
        store_session("theirs")
        store_session("mine")

        revoke_all_sessions(self.user)

        self.assertTrue(is_session_live("theirs"))
        self.assertEqual(active_sessions(other).count(), 1)


class SerializeTests(TestCase):
    def test_marks_the_current_session(self):
        user = make_user()
        row = UserSession.objects.create(user=user, session_key="key-1")
        self.assertTrue(serialize_session(row, "key-1")["is_current"])
        self.assertFalse(serialize_session(row, "key-2")["is_current"])
        self.assertFalse(serialize_session(row)["is_current"])

    def test_payload_shape(self):
        user = make_user()
        row = UserSession.objects.create(
            user=user,
            session_key="key-1",
            ip_address="1.2.3.4",
            user_agent="firefox",
        )
        payload = serialize_session(row, "key-1")
        self.assertEqual(
            set(payload),
            {"id", "ip_address", "user_agent", "created_at", "last_seen_at", "is_current"},
        )
        self.assertEqual(payload["ip_address"], "1.2.3.4")


class PruneTests(TestCase):
    def test_prune_revokes_rows_without_a_live_session(self):
        user = make_user()
        live = UserSession.objects.create(user=user, session_key="live")
        stale = UserSession.objects.create(user=user, session_key="stale")
        store_session("live")

        self.assertEqual(prune_stale_sessions(), 1)
        live.refresh_from_db()
        stale.refresh_from_db()
        self.assertIsNone(live.revoked_at)
        self.assertIsNotNone(stale.revoked_at)


class SessionManagerApiTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.current_key = self.client.session.session_key

    def test_list_requires_authentication(self):
        self.client.logout()
        response = self.client.get("/auth/sessions/")
        self.assertIn(response.status_code, (401, 403))

    def test_list_returns_sessions_with_the_current_flag(self):
        UserSession.objects.create(user=self.user, session_key=self.current_key)
        UserSession.objects.create(user=self.user, session_key="other-key")

        response = self.client.get("/auth/sessions/")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["count"], 2)
        current = [item for item in payload["sessions"] if item["is_current"]]
        self.assertEqual(len(current), 1)
        self.assertEqual(
            current[0]["id"],
            UserSession.objects.get(session_key=self.current_key).pk,
        )

    def test_revoke_one_session(self):
        row = UserSession.objects.create(user=self.user, session_key="other-key")
        store_session("other-key")

        response = self.client.post(f"/auth/sessions/{row.pk}/revoke/")

        self.assertEqual(response.status_code, 200)
        self.assertFalse(is_session_live("other-key"))

    def test_cannot_revoke_another_accounts_session(self):
        other = make_user("other@greenhillacademy.ac.ug")
        row = UserSession.objects.create(user=other, session_key="theirs")
        store_session("theirs")

        response = self.client.post(f"/auth/sessions/{row.pk}/revoke/")

        self.assertEqual(response.status_code, 404)
        self.assertTrue(is_session_live("theirs"))

    def test_revoke_others_keeps_this_browser(self):
        UserSession.objects.create(user=self.user, session_key=self.current_key)
        other = UserSession.objects.create(user=self.user, session_key="other-key")
        store_session(self.current_key)
        store_session("other-key")

        response = self.client.post("/auth/sessions/revoke-others/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["sessions_revoked"], 1)
        self.assertTrue(is_session_live(self.current_key))
        self.assertFalse(is_session_live(other.session_key))

    def test_revoke_all_signs_this_browser_out(self):
        UserSession.objects.create(user=self.user, session_key=self.current_key)

        response = self.client.post("/auth/sessions/revoke-all/")

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["authenticated"])
        # The session was flushed, so the next request is anonymous.
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_current_session_key_helper(self):
        class FakeSession:
            session_key = "abc"

        request = type("R", (), {"session": FakeSession()})()
        self.assertEqual(current_session_key(request), "abc")


class MiddlewareTests(TestCase):
    def setUp(self):
        self.user = make_user()

    def test_signed_in_request_creates_an_inventory_row(self):
        self.client.force_login(self.user)
        self.client.get("/auth/csrf/")

        self.assertTrue(
            UserSession.objects.filter(
                user=self.user,
                session_key=self.client.session.session_key,
            ).exists()
        )

    def test_anonymous_request_creates_nothing(self):
        self.client.get("/auth/csrf/")
        self.assertEqual(UserSession.objects.count(), 0)
