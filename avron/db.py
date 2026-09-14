"""SQLite store for all gateway configuration.

Env vars seed the database on first boot only. After that the DB is the single
source of truth and everything is editable from the web UI.

MASTER_KEY is the one exception that must stay in the environment: it encrypts
upstream tokens at rest, so it cannot live inside the thing it protects.
"""

import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet, InvalidToken

DB_PATH = os.getenv("DB_PATH", "/data/gateway.db")
_lock = threading.RLock()


# ----------------------------------------------------------------- crypto
def _fernet() -> Fernet:
    key = os.getenv("MASTER_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "MASTER_KEY is not set. Generate one with:\n"
            "  python -c \"from cryptography.fernet import Fernet; "
            'print(Fernet.generate_key().decode())"'
        )
    return Fernet(key.encode())


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode() if value else ""


def decrypt(value: str) -> str:
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken:
        # MASTER_KEY changed - stored tokens are unrecoverable.
        return ""


# ------------------------------------------------------------------- core
SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    must_change   INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS routes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix         TEXT UNIQUE NOT NULL,
    label          TEXT NOT NULL DEFAULT '',
    enabled        INTEGER NOT NULL DEFAULT 1,
    upstream_url   TEXT NOT NULL,
    upstream_token TEXT NOT NULL DEFAULT '',
    model_override TEXT NOT NULL DEFAULT '',
    mask_roles     TEXT NOT NULL DEFAULT '["user"]',
    entities       TEXT NOT NULL DEFAULT '[]',
    use_llm        INTEGER,
    timeout        REAL NOT NULL DEFAULT 300
);
CREATE TABLE IF NOT EXISTS upstreams (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    route_id       INTEGER NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    name           TEXT NOT NULL DEFAULT '',
    url            TEXT NOT NULL,
    token          TEXT NOT NULL DEFAULT '',
    model_override TEXT NOT NULL DEFAULT '',
    priority       INTEGER NOT NULL DEFAULT 1,
    weight         INTEGER NOT NULL DEFAULT 1,
    enabled        INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_upstreams_route ON upstreams(route_id);
CREATE TABLE IF NOT EXISTS patterns (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    pack       TEXT NOT NULL DEFAULT 'custom',
    entity     TEXT NOT NULL,
    name       TEXT NOT NULL,
    regex      TEXT NOT NULL,
    score      REAL NOT NULL DEFAULT 0.5,
    context    TEXT NOT NULL DEFAULT '[]',
    validator  TEXT NOT NULL DEFAULT 'none',
    enabled    INTEGER NOT NULL DEFAULT 1,
    builtin    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS packs (
    key     TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    upstream_id INTEGER NOT NULL,
    route       TEXT NOT NULL DEFAULT '',
    ms          INTEGER NOT NULL,
    ok          INTEGER NOT NULL DEFAULT 1,
    tokens_in   INTEGER NOT NULL DEFAULT 0,
    tokens_out  INTEGER NOT NULL DEFAULT 0,
    masked      INTEGER NOT NULL DEFAULT 0,
    model       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_samples_up ON samples(upstream_id, id);
CREATE TABLE IF NOT EXISTS entity_toggles (
    entity  TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS audit (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS stats (
    day       TEXT NOT NULL,
    hour      INTEGER NOT NULL,
    route     TEXT NOT NULL,
    requests  INTEGER NOT NULL DEFAULT 0,
    masked    INTEGER NOT NULL DEFAULT 0,
    errors    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, hour, route)
);
"""

DEFAULT_SETTINGS = {
    "llm_enabled": "true",
    "llm_base_url": "https://api.openai.com/v1",
    "llm_token": "",  # stored encrypted
    "llm_model": "auto:fast",
    "llm_timeout": "90",
    "llm_score": "0.75",
    "llm_entities": json.dumps(
        ["PERSON", "IN_ADDRESS", "IN_RELIGION_CASTE", "MEDICAL_CONDITION"]
    ),
    "score_threshold": "0.4",
    "crypto_key": "",
    "session_hours": "12",
    "proxy_enabled": "false",
    "proxy_url": "",  # stored encrypted, carries credentials
    "proxy_bypass": "localhost,127.0.0.1,avron",
}


def connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


_conn: Optional[sqlite3.Connection] = None


def db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = connect()
    return _conn


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------- settings
def get_setting(key: str, default: str = "") -> str:
    row = db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with _lock:
        db().execute(
            "INSERT INTO settings(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        db().commit()


def get_secret(key: str) -> str:
    return decrypt(get_setting(key))


def set_secret(key: str, value: str) -> None:
    set_setting(key, encrypt(value))


def all_settings() -> Dict[str, str]:
    return {r["key"]: r["value"] for r in db().execute("SELECT * FROM settings")}


# ------------------------------------------------------------------ audit
def audit(actor: str, action: str, detail: Any = "") -> None:
    if not isinstance(detail, str):
        detail = json.dumps(detail, default=str)[:2000]
    with _lock:
        db().execute(
            "INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)",
            (now(), actor, action, detail),
        )
        db().execute(
            "DELETE FROM audit WHERE id NOT IN "
            "(SELECT id FROM audit ORDER BY id DESC LIMIT 2000)"
        )
        db().commit()


def bump_stats(route: str, masked: int = 0, error: bool = False) -> None:
    ts = datetime.now(timezone.utc)
    with _lock:
        db().execute(
            "INSERT INTO stats(day,hour,route,requests,masked,errors) "
            "VALUES(?,?,?,1,?,?) ON CONFLICT(day,hour,route) DO UPDATE SET "
            "requests=requests+1, masked=masked+excluded.masked, "
            "errors=errors+excluded.errors",
            (ts.date().isoformat(), ts.hour, route, masked, 1 if error else 0),
        )
        db().commit()


# ------------------------------------------------------------------- init
SAMPLE_CAP = 5000


def record_sample(upstream_id: int, route: str, ms: int, ok: bool,
                  tokens_in: int = 0, tokens_out: int = 0, masked: int = 0,
                  model: str = "") -> None:
    """One row per request, capped. Percentiles need the distribution, not a
    running average, so the rows are kept rather than aggregated on write."""
    with _lock:
        db().execute(
            "INSERT INTO samples(ts,upstream_id,route,ms,ok,tokens_in,"
            "tokens_out,masked,model) VALUES(?,?,?,?,?,?,?,?,?)",
            (now(), upstream_id, route, int(ms), 1 if ok else 0,
             tokens_in, tokens_out, masked, model[:80]),
        )
        db().execute(
            "DELETE FROM samples WHERE id <= "
            "(SELECT MAX(id) - ? FROM samples)", (SAMPLE_CAP,)
        )
        db().commit()


def _migrate() -> None:
    """Add columns and fold single-upstream routes into the pool table."""
    cols = {r["name"] for r in db().execute("PRAGMA table_info(routes)")}
    if "strategy" not in cols:
        db().execute(
            "ALTER TABLE routes ADD COLUMN strategy TEXT NOT NULL DEFAULT 'failover'"
        )
    if "retries" not in cols:
        db().execute("ALTER TABLE routes ADD COLUMN retries INTEGER NOT NULL DEFAULT 2")

    ucols = {r["name"] for r in db().execute("PRAGMA table_info(upstreams)")}
    if "provider_type" not in ucols:
        db().execute(
            "ALTER TABLE upstreams ADD COLUMN provider_type TEXT NOT NULL "
            "DEFAULT 'openai'"
        )

    pcols = {r["name"] for r in db().execute("PRAGMA table_info(patterns)")}
    if "pack" not in pcols:
        db().execute(
            "ALTER TABLE patterns ADD COLUMN pack TEXT NOT NULL DEFAULT 'custom'"
        )
        # Everything that shipped before packs existed was the India set.
        db().execute("UPDATE patterns SET pack='india' WHERE builtin=1")
        db().execute(
            "UPDATE patterns SET pack='network' WHERE builtin=1 AND entity IN "
            "('IP_ADDRESS','MAC_ADDRESS')"
        )

    # Routes created before pools existed carry their upstream inline.
    for row in db().execute("SELECT * FROM routes").fetchall():
        has = db().execute(
            "SELECT 1 FROM upstreams WHERE route_id=? LIMIT 1", (row["id"],)
        ).fetchone()
        if has:
            continue
        url = row["upstream_url"] if "upstream_url" in row.keys() else ""
        if not url:
            continue
        db().execute(
            "INSERT INTO upstreams(route_id,name,url,token,model_override,"
            "priority,weight,enabled) VALUES(?,?,?,?,?,1,1,1)",
            (row["id"], "Primary", url,
             row["upstream_token"] if "upstream_token" in row.keys() else "",
             row["model_override"] if "model_override" in row.keys() else ""),
        )
    # Corrections to seeded patterns that shipped with an earlier version.
    # Only touches rows still carrying the original value, so an edit made in
    # the console is never overwritten.
    db().execute(
        "UPDATE patterns SET validator='bank_not_mobile' "
        "WHERE entity='IN_BANK_ACCOUNT' AND validator='not_repdigit' AND builtin=1"
    )
    db().execute(
        "UPDATE patterns SET score=0.75 "
        "WHERE entity='IN_PHONE_NUMBER' AND name='Mobile' AND score=0.6 AND builtin=1"
    )
    db().commit()


def init(seed_recognizers: List[dict], all_entities: List[str]) -> Optional[str]:
    """Create schema and seed from env on first boot.

    Returns the generated admin password if this was a first boot, else None.
    """
    with _lock:
        db().executescript(SCHEMA)
        db().commit()
        _migrate()

        # ---- settings: env seeds the DB once, then never again ----
        existing = all_settings()
        env_map = {
            "llm_enabled": os.getenv("USE_LLM"),
            "llm_base_url": os.getenv("OPENAI_BASE_URL"),
            "llm_model": os.getenv("LLM_MODEL"),
            "llm_timeout": os.getenv("LLM_TIMEOUT"),
            "llm_score": os.getenv("LLM_SCORE"),
            "score_threshold": os.getenv("SCORE_THRESHOLD"),
        }
        for key, default in DEFAULT_SETTINGS.items():
            if key in existing:
                continue
            value = env_map.get(key) or default
            if key in ("llm_token", "crypto_key", "proxy_url"):
                src = os.getenv(
                    {"llm_token": "OPENAI_API_KEY", "crypto_key": "CRYPTO_KEY",
                     "proxy_url": "HTTPS_PROXY"}[key], ""
                )
                set_secret(key, src)
            else:
                set_setting(key, value)

        if not get_secret("crypto_key"):
            set_secret("crypto_key", secrets.token_urlsafe(24)[:32])

        # ---- entity toggles ----
        # ORGANIZATION is off by default: spaCy tags field labels like "SSN"
        # and "PAN" as organisations, which masks the label instead of the
        # value and makes the prompt unreadable to the chat model.
        from patterns import ENTITY_PACK, OFF_BY_DEFAULT, PACKS

        for entity in all_entities:
            pack = ENTITY_PACK.get(entity)
            if entity in OFF_BY_DEFAULT:
                on = 0
            elif pack:
                on = 1 if PACKS[pack][3] else 0
            else:
                on = 1
            db().execute(
                "INSERT OR IGNORE INTO entity_toggles(entity,enabled) VALUES(?,?)",
                (entity, on),
            )

        # ---- built-in patterns, grouped into packs, editable ----
        # New packs are added on upgrade without disturbing existing rows.
        for p in seed_recognizers:
            pack = p.get("pack", "custom")
            db().execute(
                "INSERT OR IGNORE INTO packs(key,enabled) VALUES(?,?)",
                (pack, 1 if p.get("pack_default_on") else 0),
            )
            exists = db().execute(
                "SELECT 1 FROM patterns WHERE builtin=1 AND pack=? AND name=? "
                "AND entity=?", (pack, p["name"], p["entity"])
            ).fetchone()
            if exists:
                continue
            on = db().execute(
                "SELECT enabled FROM packs WHERE key=?", (pack,)
            ).fetchone()["enabled"]
            db().execute(
                "INSERT INTO patterns(pack,entity,name,regex,score,context,"
                "validator,enabled,builtin) VALUES(?,?,?,?,?,?,?,?,1)",
                (
                    pack,
                    p["entity"],
                    p["name"],
                    p["regex"],
                    p["score"],
                    json.dumps(p.get("context", [])),
                    p.get("validator", "none"),
                    on,
                ),
            )

        # ---- default route ----
        if not db().execute("SELECT 1 FROM routes LIMIT 1").fetchone():
            cur = db().execute(
                "INSERT INTO routes(prefix,label,upstream_url,upstream_token,"
                "mask_roles,entities,use_llm) VALUES(?,?,?,?,?,?,NULL)",
                (
                    "/v1",
                    "Default",
                    get_setting("llm_base_url"),
                    encrypt(os.getenv("OPENAI_API_KEY", "")),
                    json.dumps(["user"]),
                    json.dumps([]),  # empty = all enabled entities
                ),
            )
            db().execute(
                "INSERT INTO upstreams(route_id,name,url,token,priority,weight,"
                "provider_type) VALUES(?,?,?,?,1,1,?)",
                (cur.lastrowid, "OpenAI",
                 os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
                 encrypt(os.getenv("OPENAI_API_KEY", "")), "openai"),
            )

        # ---- first admin ----
        first_password = None
        if not db().execute("SELECT 1 FROM users LIMIT 1").fetchone():
            from auth import hash_password

            first_password = secrets.token_urlsafe(12)
            db().execute(
                "INSERT INTO users(username,password_hash,must_change,created_at) "
                "VALUES(?,?,1,?)",
                ("admin", hash_password(first_password), now()),
            )
            audit("system", "bootstrap", "created admin user")

        db().commit()
        return first_password
