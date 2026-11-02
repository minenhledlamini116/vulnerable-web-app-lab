"""Proves each flaw exists in vulnerable/ and is gone in fixed/.
Run from the repo root with:  python -m unittest -v
"""
import importlib.util
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_app(folder):
    path = ROOT / folder / "app.py"
    spec = importlib.util.spec_from_file_location(f"{folder}_app", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    tmp = tempfile.mkdtemp()
    return module.create_app(os.path.join(tmp, "test.db")), os.path.join(tmp, "test.db")


class Base(unittest.TestCase):
    folder = None

    def setUp(self):
        self.app, self.db_path = load_app(self.folder)
        self.client = self.app.test_client()

    def login(self, user, pw):
        return self.client.post("/login", data={"username": user, "password": pw})


class VulnerableAppTests(Base):
    folder = "vulnerable"

    def test_sql_injection_bypasses_login(self):
        resp = self.login("admin'--", "anything")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Welcome admin", resp.data)

    def test_reflected_xss(self):
        payload = "<script>alert(1)</script>"
        resp = self.client.get("/search", query_string={"q": payload})
        self.assertIn(payload.encode(), resp.data)

    def test_idor_reads_another_users_note(self):
        self.login("alice", "alice123")
        resp = self.client.get("/notes/2")
        self.assertIn(b"Bob private note", resp.data)

    def test_passwords_stored_in_plain_text(self):
        row = sqlite3.connect(self.db_path).execute(
            "SELECT password FROM users WHERE username='alice'"
        ).fetchone()
        self.assertEqual(row[0], "alice123")

    def test_no_security_headers(self):
        resp = self.client.get("/")
        self.assertNotIn("Content-Security-Policy", resp.headers)
        self.assertNotIn("X-Frame-Options", resp.headers)


class FixedAppTests(Base):
    folder = "fixed"

    def test_sql_injection_blocked(self):
        resp = self.login("admin'--", "anything")
        self.assertEqual(resp.status_code, 401)

    def test_normal_login_still_works(self):
        resp = self.login("alice", "alice123")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Welcome alice", resp.data)

    def test_xss_is_escaped(self):
        payload = "<script>alert(1)</script>"
        resp = self.client.get("/search", query_string={"q": payload})
        self.assertNotIn(payload.encode(), resp.data)
        self.assertIn(b"&lt;script&gt;", resp.data)

    def test_idor_blocked_but_own_note_works(self):
        self.login("alice", "alice123")
        self.assertEqual(self.client.get("/notes/2").status_code, 404)
        self.assertIn(b"Alice private note", self.client.get("/notes/1").data)

    def test_passwords_are_hashed(self):
        row = sqlite3.connect(self.db_path).execute(
            "SELECT password_hash FROM users WHERE username='alice'"
        ).fetchone()
        self.assertNotEqual(row[0], "alice123")
        self.assertTrue(row[0].startswith(("scrypt:", "pbkdf2:")))

    def test_security_headers_present(self):
        resp = self.client.get("/")
        self.assertIn("Content-Security-Policy", resp.headers)
        self.assertEqual(resp.headers["X-Frame-Options"], "DENY")
        self.assertEqual(resp.headers["X-Content-Type-Options"], "nosniff")


if __name__ == "__main__":
    unittest.main()
