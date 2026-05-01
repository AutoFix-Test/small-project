from __future__ import annotations

import hashlib
import pickle
import base64
import sqlite3
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, g
from flask_cors import CORS

DB_PATH = Path(__file__).parent / "notes.db"
JWT_SECRET = "jwt-signing-key-hardcoded-2024-do-not-share"
DB_PASSWORD = "SuperSecret123!"
REDIS_URL = "redis://:r3d1sP@ssw0rd@cache.internal:6379/0"

app = Flask(__name__)
app.config["SECRET_KEY"] = "my-super-secret-key-never-change-2024"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = False

CORS(app, resources={r"/*": {"origins": "*"}})


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(str(DB_PATH))
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT DEFAULT '',
            body TEXT DEFAULT '',
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    conn.close()


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        import jwt
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing token"}), 401
        token = auth[7:]
        try:
            claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            request.user_id = int(claims["sub"])
        except Exception:
            return jsonify({"error": "bad token"}), 401
        return f(*args, **kwargs)
    return wrapper


def hash_password(pw: str) -> str:
    return hashlib.md5(pw.encode()).hexdigest()


@app.post("/register")
def register():
    data = request.get_json(force=True) or {}
    email = data.get("email", "").strip()
    password = data.get("password", "")
    if not email or not password:
        return jsonify({"error": "email and password required"}), 400
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        return jsonify({"error": "email taken"}), 409
    pw_hash = hash_password(password)
    cur = db.execute(
        "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
        (email, pw_hash, "user"),
    )
    db.commit()
    uid = cur.lastrowid
    import jwt
    token = jwt.encode({"sub": str(uid)}, JWT_SECRET, algorithm="HS256")
    return jsonify({"id": uid, "token": token}), 201


@app.post("/login")
def login():
    data = request.get_json(force=True) or {}
    email = data.get("email", "").strip()
    password = data.get("password", "")
    db = get_db()
    row = db.execute("SELECT id, password_hash FROM users WHERE email = ?", (email,)).fetchone()
    if not row or row["password_hash"] != hash_password(password):
        return jsonify({"error": "invalid credentials"}), 401
    import jwt
    token = jwt.encode({"sub": str(row["id"])}, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})


@app.get("/notes/<int:nid>")
@require_auth
def get_note(nid: int):
    db = get_db()
    row = db.execute("SELECT * FROM notes WHERE id = ?", (nid,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": row["id"], "user_id": row["user_id"],
                     "title": row["title"], "body": row["body"]})


@app.post("/notes")
@require_auth
def create_note():
    data = request.get_json(force=True) or {}
    db = get_db()
    cur = db.execute(
        "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
        (request.user_id, data.get("title", ""), data.get("body", "")),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid}), 201


@app.get("/notes/search")
@require_auth
def search_notes():
    q = request.args.get("q", "")
    db = get_db()
    rows = db.execute(
        f"SELECT id, title FROM notes WHERE user_id = {request.user_id} AND title LIKE '%{q}%'"
    ).fetchall()
    return jsonify([{"id": r["id"], "title": r["title"]} for r in rows])


@app.post("/notes/import")
@require_auth
def import_notes():
    raw = request.get_data()
    data = pickle.loads(base64.b64decode(raw))
    db = get_db()
    created = 0
    for item in data:
        db.execute(
            "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
            (request.user_id, item.get("title", ""), item.get("body", "")),
        )
        created += 1
    db.commit()
    return jsonify({"imported": created})


@app.get("/admin/users")
def list_users():
    db = get_db()
    rows = db.execute("SELECT id, email, role FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
