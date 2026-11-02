# Vulnerable Web App Lab

A small Flask app that I broke on purpose, attacked, and then fixed. It shows five common web security flaws from the OWASP Top 10, how each one is exploited, and how the fix works.

There are two versions of the same app:

- `vulnerable/` has the flaws
- `fixed/` has the same features with every flaw closed

A test suite proves both sides. Every exploit succeeds against `vulnerable/` and fails against `fixed/`.

> Only run this on your own machine. The vulnerable app is meant to be attacked, so never put it on a public server, and never test these techniques on systems you do not own.

## The five flaws

| # | Flaw | OWASP Top 10 (2021) | Where | Fix |
|---|------|---------------------|-------|-----|
| 1 | SQL injection | A03 Injection | `/login` | Parameterised queries |
| 2 | Reflected XSS | A03 Injection | `/search` | Escape output |
| 3 | IDOR | A01 Broken Access Control | `/notes/<id>` | Check the note belongs to the logged in user |
| 4 | Plain text passwords | A02 Cryptographic Failures | users table | Hash with scrypt |
| 5 | Missing security headers and debug mode | A05 Security Misconfiguration | every response | Add headers, turn debug off |

## How to run it

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python vulnerable/app.py         # http://127.0.0.1:5001
python fixed/app.py              # http://127.0.0.1:5002
```

Run the tests from the repo root:

```bash
python -W ignore -m unittest -v
```

## Findings

### 1. SQL injection on the login

**Flaw:** the login builds its query by pasting the username and password straight into the SQL string.

```python
query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
```

**Exploit:** log in as `admin'--` with any password. The `--` turns the rest of the query into a comment, so the password check disappears.

```bash
curl -i -c jar.txt -d "username=admin'--" -d "password=x" http://127.0.0.1:5001/login
```

**Impact:** anyone can log in as any user without knowing the password.

**Fix:** pass the values as parameters so the database treats them as data and never as SQL.

```python
db().execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
```

### 2. Reflected cross site scripting on search

**Flaw:** the search page puts whatever you type straight into the HTML.

**Exploit:** open `http://127.0.0.1:5001/search?q=<script>alert(1)</script>` and the script runs in the browser.

**Impact:** an attacker can send a victim a crafted link that runs JavaScript in their session, which can steal data or act as them.

**Fix:** escape the input so the browser shows it as text, and add a Content Security Policy as a second layer.

```python
f"<h1>Results for {escape(q)}</h1>"
```

### 3. IDOR on notes

**Flaw:** `/notes/<id>` checks that you are logged in but never checks that the note is yours.

**Exploit:** log in as alice, then request `/notes/2`. That is Bob's private note.

```bash
curl -b jar.txt http://127.0.0.1:5001/notes/2
```

**Impact:** any logged in user can read every other user's notes by counting through the ids.

**Fix:** put the owner in the query so someone else's note simply does not exist for you.

```python
"SELECT body FROM notes WHERE id = ? AND owner_id = ?", (note_id, user_id)
```

### 4. Plain text passwords

**Flaw:** passwords are stored exactly as typed. Anyone who gets a copy of the database, for example through flaw 1, sees every password.

**Fix:** store only a salted hash and compare with `check_password_hash`.

```python
generate_password_hash(pw)
```

### 5. Missing security headers and debug mode

**Flaw:** the vulnerable app sends no protective headers and runs with `debug=True`, which can expose the Werkzeug debugger and detailed error pages.

**Fix:** the fixed app adds these headers to every response and runs with debug off.

| Header | What it does |
|--------|--------------|
| Content-Security-Policy | Limits where scripts and other content can load from |
| X-Content-Type-Options | Stops the browser guessing file types |
| X-Frame-Options | Stops the site being framed for clickjacking |
| Referrer-Policy | Stops leaking URLs to other sites |

## Screenshots

![SQL injection login bypass](picture1.png)
![XSS alert box](picture2.png)
![IDOR reading Bob's note](picture3.png)
![Tests passing](picture4.png)

## What I would add next

- Login rate limiting and account lockout
- CSRF protection on forms
- Running OWASP ZAP against both versions and comparing the reports
