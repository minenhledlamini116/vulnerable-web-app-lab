"""INTENTIONALLY VULNERABLE practice app. Run it on your own machine only."""
import sqlite3
from flask import Flask, request, session, make_response, abort


def create_app(db_path="vulnerable.db"):
    app = Flask(__name__)
    app.secret_key = "secret"

    def db():
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def seed():
        conn = db()
        conn.executescript("""
            DROP TABLE IF EXISTS users;
            DROP TABLE IF EXISTS notes;
            CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
            CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER, body TEXT);
            INSERT INTO users VALUES (1, 'alice', 'alice123');
            INSERT INTO users VALUES (2, 'bob', 'bobpass');
            INSERT INTO users VALUES (3, 'admin', 'Sup3rS3cret!');
            INSERT INTO notes VALUES (1, 1, 'Alice private note: my locker code is 4821');
            INSERT INTO notes VALUES (2, 2, 'Bob private note: wifi password is bluesky99');
            INSERT INTO notes VALUES (3, 3, 'Admin note: backup runs at midnight');
        """)
        conn.commit()
        conn.close()

    seed()

    @app.route("/")
    def home():
        return "Vulnerable lab. Try /login, /search?q=hello and /notes/1"

    @app.route("/login", methods=["POST"])
    def login():
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        query = (
            "SELECT id, username FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        try:
            row = db().execute(query).fetchone()
        except sqlite3.Error as err:
            return f"Database error: {err} in query: {query}", 500
        if row is None:
            return "Wrong username or password", 401
        session["user_id"] = row["id"]
        return f"Welcome {row['username']}"

    @app.route("/search")
    def search():
        q = request.args.get("q", "")
        return make_response(f"<h1>Results for {q}</h1><p>Nothing found.</p>")

    @app.route("/notes/<int:note_id>")
    def note(note_id):
        if "user_id" not in session:
            abort(401)
        row = db().execute("SELECT body FROM notes WHERE id = ?", (note_id,)).fetchone()
        if row is None:
            abort(404)
        return row["body"]

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5001, debug=True)
