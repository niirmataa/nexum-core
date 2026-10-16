"""Serial tests of the demo HTTP flow, not cryptographic verification."""
import http.client
import json
import threading
import unittest

from server import DEMO_PASSWORD, DemoServer


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = DemoServer(("127.0.0.1", 0))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.cookie, self.csrf = "", ""
        _, body = self.request("GET", "/api/demo/bootstrap")
        self.csrf = body["csrf"]

    def request(self, method, path, data=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        base = {"Cookie": self.cookie}
        if method == "POST":
            base.update({"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{self.server.server_port}", "X-Nexum-CSRF": self.csrf})
        base.update(headers or {})
        connection.request(method, path, json.dumps(data) if data is not None else None, base)
        response = connection.getresponse()
        cookie = response.getheader("Set-Cookie")
        if cookie:
            self.cookie = cookie.split(";", 1)[0]
        body = response.read()
        status = response.status
        kind = response.getheader("Content-Type", "")
        connection.close()
        return status, json.loads(body) if kind.startswith("application/json") else body.decode()

    def challenge(self):
        self.assertEqual(self.request("POST", "/api/demo/connect", {})[0], 200)
        self.assertEqual(self.request("POST", "/api/demo/select", {"escrow_id": "NX-DEMO-041"})[0], 200)
        status, body = self.request("POST", "/api/demo/challenge/prepare", {})
        self.assertEqual(status, 200)
        return body["challenge"]["id"]

    def authorize(self):
        challenge_id = self.challenge()
        status, body = self.request("POST", "/api/demo/challenge/confirm", {"challenge_id": challenge_id, "password": DEMO_PASSWORD})
        self.assertEqual(status, 200)
        self.assertTrue(body["simulated_signature"])
        return challenge_id

    def test_full_demo_flow_and_lock(self):
        self.authorize()
        status, body = self.request("GET", "/api/demo/status")
        self.assertEqual(status, 200)
        self.assertTrue(body["demo"])
        self.assertEqual(body["snapshot"]["id"], "NX-DEMO-041")
        self.assertNotIn("password", body)
        self.request("POST", "/api/demo/lock", {})
        self.assertEqual(self.request("GET", "/api/demo/status")[0], 401)

    def test_wrong_password_does_not_grant_access(self):
        challenge_id = self.challenge()
        status, body = self.request("POST", "/api/demo/challenge/confirm", {"challenge_id": challenge_id, "password": "wrong-demo-password"})
        self.assertEqual((status, body["error"]), (403, "WRONG_PASSWORD"))
        self.assertEqual(self.request("GET", "/api/demo/status")[0], 401)

    def test_password_attempt_limit_can_be_recovered_with_new_challenge(self):
        challenge_id = self.challenge()
        for _ in range(5):
            self.assertEqual(self.request("POST", "/api/demo/challenge/confirm", {"challenge_id": challenge_id, "password": "wrong-demo-password"})[0], 403)
        status, body = self.request("POST", "/api/demo/challenge/confirm", {"challenge_id": challenge_id, "password": DEMO_PASSWORD})
        self.assertEqual((status, body["error"]), (429, "TOO_MANY_ATTEMPTS"))
        _, prepared = self.request("POST", "/api/demo/challenge/prepare", {})
        new_id = prepared["challenge"]["id"]
        self.assertNotEqual(new_id, challenge_id)
        self.assertEqual(self.request("POST", "/api/demo/challenge/confirm", {"challenge_id": new_id, "password": DEMO_PASSWORD})[0], 200)

    def test_consumed_challenge_cannot_be_replayed(self):
        challenge_id = self.authorize()
        status, body = self.request("POST", "/api/demo/challenge/confirm", {"challenge_id": challenge_id, "password": DEMO_PASSWORD})
        self.assertEqual((status, body["error"]), (409, "CHALLENGE_USED"))

    def test_expired_challenge_and_access(self):
        challenge_id = self.challenge()
        self.request("POST", "/api/demo/scenario", {"scenario": "expire_challenge"})
        status, body = self.request("POST", "/api/demo/challenge/confirm", {"challenge_id": challenge_id, "password": DEMO_PASSWORD})
        self.assertEqual((status, body["error"]), (410, "CHALLENGE_EXPIRED"))
        self.authorize()
        self.request("POST", "/api/demo/scenario", {"scenario": "expire_access"})
        self.assertEqual(self.request("GET", "/api/demo/status")[0], 401)

    def test_challenge_cannot_be_swapped(self):
        old_id = self.challenge()
        self.request("POST", "/api/demo/select", {"escrow_id": "NX-DEMO-042"})
        self.request("POST", "/api/demo/challenge/prepare", {})
        status, body = self.request("POST", "/api/demo/challenge/confirm", {"challenge_id": old_id, "password": DEMO_PASSWORD})
        self.assertEqual((status, body["error"]), (409, "CHALLENGE_MISMATCH"))

    def test_offline_keeps_last_snapshot_timestamp(self):
        self.authorize()
        _, before = self.request("GET", "/api/demo/status")
        self.request("POST", "/api/demo/scenario", {"scenario": "offline"})
        _, after = self.request("GET", "/api/demo/status")
        self.assertFalse(after["fresh"])
        self.assertEqual(before["snapshot"]["observed_at"], after["snapshot"]["observed_at"])
        self.assertEqual(self.request("POST", "/api/demo/challenge/prepare", {})[0], 503)

    def test_foreign_origin_and_missing_csrf_are_refused(self):
        self.assertEqual(self.request("POST", "/api/demo/connect", {}, {"Origin": "https://example.invalid"})[0], 403)
        self.assertEqual(self.request("POST", "/api/demo/connect", {}, {"X-Nexum-CSRF": ""})[0], 403)
        self.assertEqual(self.request("GET", "/api/demo/bootstrap", headers={"Host": "example.invalid"})[0], 403)

    def test_second_local_session_has_no_access(self):
        self.authorize()
        self.cookie = ""
        _, bootstrap = self.request("GET", "/api/demo/bootstrap")
        self.assertEqual(bootstrap["phase"], "connect")
        self.assertEqual(self.request("GET", "/api/demo/status")[0], 409)

    def test_system_status_is_live_readonly(self):
        status, body = self.request("GET", "/api/system/status")
        self.assertEqual(status, 200)
        self.assertTrue(body["live"])
        self.assertEqual(len(body["services"]), 5)
        self.assertIn("trust", body)
        self.assertIn("agents", body)
        status, _ = self.request("POST", "/api/system/status", {})
        self.assertEqual(status, 404)

    def test_real_data_and_transaction_routes_are_absent(self):
        self.request("POST", "/api/demo/connect", {})
        self.assertEqual(self.request("POST", "/api/demo/select", {"escrow_id": "real-escrow"})[0], 400)
        for path in ("/api/register", "/api/login", "/api/demo/refund", "/api/demo/submit", "/api/demo/delivered"):
            self.assertEqual(self.request("POST", path, {})[0], 404)
        self.assertEqual(self.request("GET", "/../server.py")[0], 404)

    def test_page_labels_mock_data_and_local_assets(self):
        status, text = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("dane demonstracyjne", text)
        self.assertIn("Brak rzeczywistego połączenia", text)
        self.assertNotIn('src="https://', text)
        self.assertNotIn('href="https://', text)


if __name__ == "__main__":
    unittest.main()
