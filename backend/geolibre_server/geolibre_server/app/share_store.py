"""Persistent storage and authentication primitives for the local Share service."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("La contraseña debe tener al menos 12 caracteres.")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = encoded.split("$")
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(
            password.encode(),
            salt=bytes.fromhex(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(bytes.fromhex(expected)),
        )
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


def secret_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def slugify(value: str, fallback: str = "project") -> str:
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    normalized = re.sub(r"\.geolibre\.json$", "", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"[^a-zA-Z0-9]+", "-", normalized).strip("-").lower()
    return (normalized or fallback)[:80]


def valid_username(value: str) -> bool:
    return re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{2,31}", value) is not None


class ShareStore:
    """Small SQLite repository used by both the API and the administration CLI."""

    def __init__(self, data_dir: str | Path | None = None):
        root = Path(data_dir or os.environ.get("GEOLIBRE_SHARE_DATA_DIR", "/data/share"))
        root.mkdir(parents=True, exist_ok=True)
        root.chmod(0o700)
        self.db_path = root / "share.sqlite3"
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        with self.connect() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    password_hash TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS api_tokens (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    token_prefix TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT,
                    revoked_at TEXT
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    session_hash TEXT NOT NULL UNIQUE,
                    csrf_token TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    slug TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    visibility TEXT NOT NULL CHECK (visibility IN ('public','unlisted','private')),
                    content TEXT NOT NULL,
                    views INTEGER NOT NULL DEFAULT 0,
                    version_count INTEGER NOT NULL DEFAULT 1,
                    featured INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(user_id, slug)
                );
                CREATE INDEX IF NOT EXISTS projects_public_updated
                    ON projects(visibility, featured, updated_at DESC);
                """
            )
        self.db_path.chmod(0o600)

    def create_user(self, username: str, password: str, *, admin: bool = False) -> dict[str, Any]:
        username = username.strip()
        if not valid_username(username):
            raise ValueError("Use 3 a 32 caracteres: letras, números, guion o guion bajo.")
        with self.connect() as db:
            cursor = db.execute(
                "INSERT INTO users(username,password_hash,is_admin,created_at) VALUES(?,?,?,?)",
                (username, hash_password(password), int(admin), utc_now()),
            )
            return {"id": cursor.lastrowid, "username": username, "is_admin": admin}

    def authenticate_password(self, username: str, password: str) -> sqlite3.Row | None:
        with self.connect() as db:
            user = db.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username.strip(),)
            ).fetchone()
        return user if user and verify_password(password, user["password_hash"]) else None

    def get_user(self, user_id: int) -> sqlite3.Row | None:
        with self.connect() as db:
            return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def get_user_by_name(self, username: str) -> sqlite3.Row | None:
        with self.connect() as db:
            return db.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
            ).fetchone()

    def change_password(self, user_id: int, password: str) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(password), user_id),
            )
            db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

    def create_session(self, user_id: int, expires_at: int) -> tuple[str, str]:
        session = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(datetime.now().timestamp()),))
            db.execute(
                """INSERT INTO sessions(user_id,session_hash,csrf_token,created_at,expires_at)
                   VALUES(?,?,?,?,?)""",
                (user_id, secret_hash(session), csrf, utc_now(), expires_at),
            )
        return session, csrf

    def session_user(self, session: str, now: int) -> tuple[sqlite3.Row, str] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT users.*, sessions.csrf_token
                   FROM sessions JOIN users ON users.id = sessions.user_id
                   WHERE sessions.session_hash = ? AND sessions.expires_at > ?""",
                (secret_hash(session), now),
            ).fetchone()
        return (row, row["csrf_token"]) if row else None

    def delete_session(self, session: str) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE session_hash = ?", (secret_hash(session),))

    def create_token(self, user_id: int, name: str) -> str:
        token = "glb_" + secrets.token_urlsafe(32)
        with self.connect() as db:
            db.execute(
                """INSERT INTO api_tokens(user_id,name,token_hash,token_prefix,created_at)
                   VALUES(?,?,?,?,?)""",
                (user_id, name.strip()[:80] or "GeoLibre", secret_hash(token), token[:12], utc_now()),
            )
        return token

    def authenticate_token(self, token: str) -> sqlite3.Row | None:
        if not token.startswith("glb_"):
            return None
        with self.connect() as db:
            row = db.execute(
                """SELECT users.*, api_tokens.id AS token_id
                   FROM api_tokens JOIN users ON users.id = api_tokens.user_id
                   WHERE api_tokens.token_hash = ? AND api_tokens.revoked_at IS NULL""",
                (secret_hash(token),),
            ).fetchone()
            if row:
                db.execute(
                    "UPDATE api_tokens SET last_used_at = ? WHERE id = ?",
                    (utc_now(), row["token_id"]),
                )
        return row

    def list_tokens(self, user_id: int) -> list[sqlite3.Row]:
        with self.connect() as db:
            return db.execute(
                """SELECT id,name,token_prefix,created_at,last_used_at
                   FROM api_tokens WHERE user_id = ? AND revoked_at IS NULL
                   ORDER BY created_at DESC""",
                (user_id,),
            ).fetchall()

    def revoke_token(self, user_id: int, token_id: int) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND user_id = ?",
                (utc_now(), token_id, user_id),
            )

    def upsert_project(
        self, user_id: int, slug: str, title: str, visibility: str, content: str
    ) -> sqlite3.Row:
        now = utc_now()
        with self.connect() as db:
            db.execute(
                """INSERT INTO projects(
                       user_id,slug,title,visibility,content,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(user_id,slug) DO UPDATE SET
                       title=excluded.title, visibility=excluded.visibility,
                       content=excluded.content, updated_at=excluded.updated_at,
                       version_count=projects.version_count+1""",
                (user_id, slug, title[:100], visibility, content, now, now),
            )
            return db.execute(
                "SELECT * FROM projects WHERE user_id = ? AND slug = ?", (user_id, slug)
            ).fetchone()

    def list_public(self, limit: int, offset: int, featured: bool) -> list[sqlite3.Row]:
        clause = "AND projects.featured = 1" if featured else ""
        with self.connect() as db:
            return db.execute(
                f"""SELECT projects.*, users.username FROM projects
                    JOIN users ON users.id = projects.user_id
                    WHERE projects.visibility = 'public' {clause}
                    ORDER BY projects.updated_at DESC LIMIT ? OFFSET ?""",
                (limit, offset),
            ).fetchall()

    def list_user_projects(self, user_id: int) -> list[sqlite3.Row]:
        with self.connect() as db:
            return db.execute(
                """SELECT projects.*, users.username FROM projects
                   JOIN users ON users.id = projects.user_id
                   WHERE projects.user_id = ? ORDER BY projects.updated_at DESC""",
                (user_id,),
            ).fetchall()

    def find_project(self, username: str, slug: str) -> sqlite3.Row | None:
        with self.connect() as db:
            return db.execute(
                """SELECT projects.*, users.username FROM projects
                   JOIN users ON users.id = projects.user_id
                   WHERE users.username = ? COLLATE NOCASE AND projects.slug = ?""",
                (username, slug),
            ).fetchone()

    def increment_views(self, project_id: int) -> None:
        with self.connect() as db:
            db.execute("UPDATE projects SET views = views + 1 WHERE id = ?", (project_id,))
