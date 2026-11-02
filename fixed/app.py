"""The same app with every flaw fixed."""
import sqlite3
from flask import Flask, request, session, make_response, abort
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash


def create_app(db_path="fixed.db"):
    app = Flask(__name__)
    app.secret_key = "change-me-in-real-life-and-load-it-from-an-environment-variable"
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

    def db():
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def seed():
        conn = db()
        conn.executescript("""
            DROP TABLE IF EXISTS users;
            DROP TABLE IF EXISTS notes;
            CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT);
            CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER, body TEXT);
            INSERT INTO notes VALUES (1, 1, 'Alice private note: my locker code is 4821');
            INSERT INTO notes VALUES (2, 2, 'Bob private note: wifi password is bluesky99');
            INSERT INTO notes VALUES (3, 3, 'Admin note: backup runs at midnight');
        """)
        for uid, name, pw in [(1, "alice", "alice123"), (2, "bob", "bobpass"), (3, "admin", "Sup3rS3cret!")]:
            conn.execute(
                "INSERT INTO users VALUES (?, ?, ?)", (uid, name, generate_password_hash(pw))
            )
        conn.commit()
        conn.close()

    seed()

    @app.after_request
    def add_security_headers(resp):
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.route("/")
    def home():
        return "Fixed lab. Try /login, /search?q=hello and /notes/1"

    @app.route("/login", methods=["POST"])
    def login():
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        row = db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None or not check_password_hash(row["password_hash"], password):
            return "Wrong username or password", 401
        session["user_id"] = row["id"]
        return f"Welcome {escape(row['username'])}"

    @app.route("/search")
    def search():
        q = request.args.get("q", "")
        return make_response(f"<h1>Results for {escape(q)}</h1><p>Nothing found.</p>")

    @app.route("/notes/<int:note_id>")
    def note(note_id):
        user_id = session.get("user_id")
        if user_id is None:
            abort(401)
        row = db().execute(
            "SELECT body FROM notes WHERE id = ? AND owner_id = ?", (note_id, user_id)
        ).fetchone()
        if row is None:
            abort(404)
        return row["body"]

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5002, debug=False)
