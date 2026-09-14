"""Admin API. Every endpoint requires a valid session cookie."""

import json
import re
from typing import List, Optional

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

import auth
import db
from balancer import STRATEGIES, pool
from config import config
from patterns import (
    ALL_ENTITIES,
    LLM_ONLY_ENTITIES,
    VALIDATOR_HELP,
    regex_problem,
)

router = APIRouter(prefix="/api", tags=["admin"])


def me(request: Request) -> dict:
    return auth.current_user(request)


def admin(request: Request) -> dict:
    return auth.require_admin(request)


# ------------------------------------------------------------------ auth
class Credentials(BaseModel):
    username: str
    password: str


@router.post("/login")
def do_login(body: Credentials, response: Response):
    token = auth.login(body.username.strip(), body.password)
    response.set_cookie(
        auth.COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=auth.secure_cookie(),
        max_age=int(db.get_setting("session_hours", "12")) * 3600,
        path="/",
    )
    return {"ok": True}


@router.post("/logout")
def do_logout(request: Request, response: Response):
    token = request.cookies.get(auth.COOKIE)
    if token:
        auth.logout(token)
    response.delete_cookie(auth.COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
def whoami(user: dict = Depends(me)):
    return {
        "username": user["username"],
        "role": user.get("role", "admin"),
        "must_change": bool(user["must_change"]),
    }


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


@router.post("/account/password")
def change_password(body: PasswordChange, user: dict = Depends(me)):
    row = db.db().execute(
        "SELECT password_hash FROM users WHERE id=?", (user["id"],)
    ).fetchone()
    if not auth.verify_password(body.current_password, row["password_hash"]):
        raise HTTPException(400, "Current password is incorrect.")
    problem = auth.password_problem(body.new_password)
    if problem:
        raise HTTPException(400, problem)
    db.db().execute(
        "UPDATE users SET password_hash=?, must_change=0 WHERE id=?",
        (auth.hash_password(body.new_password), user["id"]),
    )
    db.db().commit()
    db.audit(user["username"], "password_change")
    return {"ok": True}


# ------------------------------------------------------------ client keys
class KeyIn(BaseModel):
    name: str = ""
    expires_days: Optional[int] = None
    routes: List[str] = []


def _key_row(r, mine: bool) -> dict:
    return {
        "id": r["id"], "name": r["name"], "prefix": r["prefix"] + "…",
        "owner": r["username"] or "(deleted)", "enabled": bool(r["enabled"]),
        "created_at": r["created_at"], "expires_at": r["expires_at"],
        "last_used": r["last_used"], "uses": r["uses"],
        "routes": json.loads(r["routes"] or "[]"), "mine": mine,
    }


@router.get("/keys")
def list_keys(user: dict = Depends(me)):
    """Admins see every key; everyone else sees only their own."""
    sql = ("SELECT k.*, u.username FROM api_keys k "
           "LEFT JOIN users u ON u.id = k.user_id ")
    if user.get("role") == "admin":
        rows = db.db().execute(sql + "ORDER BY k.id DESC").fetchall()
    else:
        rows = db.db().execute(
            sql + "WHERE k.user_id = ? ORDER BY k.id DESC", (user["id"],)
        ).fetchall()
    return {
        "required": auth.client_key_required(),
        "keys": [_key_row(r, r["user_id"] == user["id"]) for r in rows],
    }


@router.post("/keys")
def create_key(body: KeyIn, user: dict = Depends(me)):
    """The full key is returned once and never stored in recoverable form."""
    full, digest, prefix = auth.new_api_key()
    expires = None
    if body.expires_days and body.expires_days > 0:
        expires = (
            datetime.now(timezone.utc) + timedelta(days=body.expires_days)
        ).isoformat(timespec="seconds")
    cur = db.db().execute(
        "INSERT INTO api_keys(key_hash,prefix,name,user_id,enabled,created_at,"
        "expires_at,routes) VALUES(?,?,?,?,1,?,?,?)",
        (digest, prefix, body.name.strip()[:60] or "unnamed", user["id"],
         db.now(), expires, json.dumps(body.routes)),
    )
    db.db().commit()
    db.audit(user["username"], "key_create", body.name or "unnamed")
    return {"id": cur.lastrowid, "key": full,
            "note": "Copy this now. It is not shown again."}


@router.put("/keys/{kid}")
def toggle_key(kid: int, body: dict, user: dict = Depends(me)):
    row = db.db().execute("SELECT * FROM api_keys WHERE id=?", (kid,)).fetchone()
    if not row:
        raise HTTPException(404, "Key not found.")
    if row["user_id"] != user["id"] and user.get("role") != "admin":
        raise HTTPException(403, "That key belongs to someone else.")
    db.db().execute(
        "UPDATE api_keys SET enabled=?, name=COALESCE(?,name) WHERE id=?",
        (1 if body.get("enabled") else 0, (body.get("name") or None), kid),
    )
    db.db().commit()
    db.audit(user["username"], "key_update", row["name"])
    return {"ok": True}


@router.delete("/keys/{kid}")
def revoke_key(kid: int, user: dict = Depends(me)):
    row = db.db().execute("SELECT * FROM api_keys WHERE id=?", (kid,)).fetchone()
    if not row:
        raise HTTPException(404, "Key not found.")
    if row["user_id"] != user["id"] and user.get("role") != "admin":
        raise HTTPException(403, "That key belongs to someone else.")
    db.db().execute("DELETE FROM api_keys WHERE id=?", (kid,))
    db.db().commit()
    db.audit(user["username"], "key_revoke", row["name"])
    return {"ok": True}


# ----------------------------------------------------------------- users
@router.get("/users")
def list_users(user: dict = Depends(admin)):
    rows = db.db().execute(
        "SELECT id, username, created_at, must_change, role FROM users ORDER BY id"
    ).fetchall()
    return [dict(r) for r in rows]


class NewUser(BaseModel):
    username: str
    password: str
    role: str = "user"


@router.post("/users")
def add_user(body: NewUser, user: dict = Depends(admin)):
    name = body.username.strip()
    if not re.fullmatch(r"[a-zA-Z0-9._-]{3,32}", name):
        raise HTTPException(400, "Username must be 3-32 chars: letters, digits . _ -")
    problem = auth.password_problem(body.password)
    if problem:
        raise HTTPException(400, problem)
    try:
        db.db().execute(
            "INSERT INTO users(username,password_hash,must_change,created_at,"
            "role) VALUES(?,?,0,?,?)",
            (name, auth.hash_password(body.password), db.now(),
             "admin" if body.role == "admin" else "user"),
        )
        db.db().commit()
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "That username already exists.")
    db.audit(user["username"], "user_create", name)
    return {"ok": True}


@router.delete("/users/{user_id}")
def remove_user(user_id: int, user: dict = Depends(admin)):
    if user_id == user["id"]:
        raise HTTPException(400, "You cannot delete your own account.")
    admins = db.db().execute(
        "SELECT COUNT(*) c FROM users WHERE role='admin'"
    ).fetchone()["c"]
    target = db.db().execute(
        "SELECT role FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if target and target["role"] == "admin" and admins <= 1:
        raise HTTPException(400, "At least one administrator must remain.")
    db.db().execute("DELETE FROM users WHERE id=?", (user_id,))
    db.db().commit()
    db.audit(user["username"], "user_delete", str(user_id))
    return {"ok": True}


# -------------------------------------------------------------- settings
SECRET_KEYS = {"llm_token", "crypto_key", "proxy_url"}


@router.get("/settings")
def get_settings(user: dict = Depends(admin)):
    out = {}
    for key, value in db.all_settings().items():
        # Secrets are never returned. The UI shows whether one is set.
        out[key] = "••••••••" if key in SECRET_KEYS and value else (
            "" if key in SECRET_KEYS else value
        )
    out["_entities_all"] = ALL_ENTITIES
    out["_entities_llm_only"] = LLM_ONLY_ENTITIES
    out["_validators"] = VALIDATOR_HELP
    return out


@router.put("/settings")
def put_settings(body: dict, user: dict = Depends(admin)):
    changed = []
    for key, value in body.items():
        if key.startswith("_"):
            continue
        if key in SECRET_KEYS:
            if value and value != "••••••••":
                db.set_secret(key, value)
                changed.append(key)
            continue
        if isinstance(value, (list, dict)):
            value = json.dumps(value)
        if isinstance(value, bool):
            value = "true" if value else "false"
        db.set_setting(key, value)
        changed.append(key)
    db.audit(user["username"], "settings_update", changed)
    return {"ok": True}


# -------------------------------------------------------------- entities
@router.get("/entities")
def get_entities(user: dict = Depends(admin)):
    rows = db.db().execute("SELECT * FROM entity_toggles ORDER BY entity").fetchall()
    counts = {
        r["entity"]: r["n"]
        for r in db.db().execute(
            "SELECT entity, COUNT(*) n FROM patterns WHERE enabled=1 GROUP BY entity"
        )
    }
    llm_entities = json.loads(db.get_setting("llm_entities", "[]") or "[]")
    return [
        {
            "entity": r["entity"],
            "enabled": bool(r["enabled"]),
            "patterns": counts.get(r["entity"], 0),
            "source": "llm" if r["entity"] in llm_entities else (
                "rules" if counts.get(r["entity"]) else "presidio"
            ),
        }
        for r in rows
    ]


@router.put("/entities")
def put_entities(body: List[dict], user: dict = Depends(admin)):
    for item in body:
        db.db().execute(
            "INSERT INTO entity_toggles(entity,enabled) VALUES(?,?) "
            "ON CONFLICT(entity) DO UPDATE SET enabled=excluded.enabled",
            (item["entity"], 1 if item.get("enabled") else 0),
        )
    db.db().commit()
    db.audit(user["username"], "entities_update", f"{len(body)} toggles")
    return {"ok": True}


# -------------------------------------------------------------- patterns
class PatternIn(BaseModel):
    pack: str = "custom"
    entity: str
    name: str
    regex: str
    score: float = Field(0.5, ge=0.0, le=1.0)
    context: List[str] = []
    validator: str = "none"
    enabled: bool = True


@router.get("/patterns")
def list_patterns(user: dict = Depends(admin)):
    rows = db.db().execute("SELECT * FROM patterns ORDER BY entity, id").fetchall()
    return [
        {**dict(r), "context": json.loads(r["context"] or "[]"),
         "pack": r["pack"] if "pack" in r.keys() else "custom",
         "enabled": bool(r["enabled"]), "builtin": bool(r["builtin"])}
        for r in rows
    ]


def _validate(p: PatternIn):
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,39}", p.entity):
        raise HTTPException(400, "Entity must be UPPER_SNAKE_CASE, 3-40 chars.")
    problem = regex_problem(p.regex)
    if problem:
        raise HTTPException(400, problem)
    if p.validator not in VALIDATOR_HELP:
        raise HTTPException(400, "Unknown validator.")


@router.post("/patterns")
def add_pattern(p: PatternIn, user: dict = Depends(admin)):
    _validate(p)
    cur = db.db().execute(
        "INSERT INTO patterns(pack,entity,name,regex,score,context,validator,"
        "enabled,builtin) VALUES(?,?,?,?,?,?,?,?,0)",
        ("custom", p.entity, p.name, p.regex, p.score, json.dumps(p.context),
         p.validator, 1 if p.enabled else 0),
    )
    db.db().execute(
        "INSERT OR IGNORE INTO entity_toggles(entity,enabled) VALUES(?,1)", (p.entity,)
    )
    db.db().commit()
    _reload_or_rollback(cur.lastrowid, user, "pattern_create", p.name)
    return {"ok": True, "id": cur.lastrowid}


@router.put("/patterns/{pid}")
def edit_pattern(pid: int, p: PatternIn, user: dict = Depends(admin)):
    _validate(p)
    before = db.db().execute("SELECT * FROM patterns WHERE id=?", (pid,)).fetchone()
    if not before:
        raise HTTPException(404, "Pattern not found.")
    db.db().execute(
        "UPDATE patterns SET entity=?,name=?,regex=?,score=?,context=?,validator=?,"
        "enabled=? WHERE id=?",
        (p.entity, p.name, p.regex, p.score, json.dumps(p.context), p.validator,
         1 if p.enabled else 0, pid),
    )
    db.db().commit()
    try:
        config.reload()
    except Exception as exc:  # noqa: BLE001
        db.db().execute(
            "UPDATE patterns SET entity=?,name=?,regex=?,score=?,context=?,"
            "validator=?,enabled=? WHERE id=?",
            (before["entity"], before["name"], before["regex"], before["score"],
             before["context"], before["validator"], before["enabled"], pid),
        )
        db.db().commit()
        config.reload()
        raise HTTPException(400, f"Rejected, previous version restored: {exc}")
    db.audit(user["username"], "pattern_update", p.name)
    return {"ok": True}


@router.delete("/patterns/{pid}")
def remove_pattern(pid: int, user: dict = Depends(admin)):
    db.db().execute("DELETE FROM patterns WHERE id=?", (pid,))
    db.db().commit()
    config.reload()
    db.audit(user["username"], "pattern_delete", str(pid))
    return {"ok": True}


def _reload_or_rollback(pid: int, user: dict, action: str, detail: str):
    try:
        config.reload()
    except Exception as exc:  # noqa: BLE001
        db.db().execute("DELETE FROM patterns WHERE id=?", (pid,))
        db.db().commit()
        config.reload()
        raise HTTPException(400, f"Pattern rejected: {exc}")
    db.audit(user["username"], action, detail)


class PatternTest(BaseModel):
    regex: str
    validator: str = "none"
    text: str


@router.post("/patterns/test")
def test_pattern(body: PatternTest, user: dict = Depends(admin)):
    problem = regex_problem(body.regex)
    if problem:
        return {"error": problem, "matches": []}
    from patterns import VALIDATORS

    validate = VALIDATORS.get(body.validator, VALIDATORS["none"])
    matches = []
    try:
        for m in re.finditer(body.regex, body.text):
            matches.append({
                "text": m.group(),
                "start": m.start(),
                "end": m.end(),
                "valid": bool(validate(m.group())),
            })
            if len(matches) >= 50:
                break
    except re.error as exc:
        return {"error": str(exc), "matches": []}
    return {"error": "", "matches": matches}


# ---------------------------------------------------------------- routes
class UpstreamIn(BaseModel):
    id: Optional[int] = None
    name: str = ""
    provider_type: str = "openai"
    url: str
    token: Optional[str] = None  # None means "keep whatever is stored"
    model_override: str = ""
    priority: int = 1
    weight: int = 1
    enabled: bool = True


class RouteIn(BaseModel):
    prefix: str
    label: str = ""
    enabled: bool = True
    mask_roles: List[str] = ["user"]
    entities: List[str] = []
    use_llm: Optional[bool] = None
    timeout: float = 300
    strategy: str = "failover"
    retries: int = 2
    upstreams: List[UpstreamIn] = []


RESERVED = ("/api", "/admin", "/static", "/health", "/analyze", "/anonymize",
            "/deanonymize", "/docs", "/openapi.json")


def _check_prefix(prefix: str) -> str:
    prefix = "/" + prefix.strip().strip("/")
    if not re.fullmatch(r"(/[a-zA-Z0-9._-]+)+", prefix):
        raise HTTPException(400, "Path must look like /v1 or /secure/v1")
    for r in RESERVED:
        if prefix == r or prefix.startswith(r + "/"):
            raise HTTPException(400, f"{prefix} collides with a reserved path.")
    return prefix


@router.get("/strategies")
def strategies(user: dict = Depends(admin)):
    return STRATEGIES


@router.get("/routes")
def list_routes(user: dict = Depends(admin)):
    out = []
    for r in config.routes():
        r = dict(r)
        r.pop("upstream_token", None)
        r["enabled"] = bool(r["enabled"])
        r["use_llm"] = None if r["use_llm"] is None else bool(r["use_llm"])
        r["upstreams"] = [
            {
                "id": u["id"], "name": u["name"], "url": u["url"],
                "provider_type": u.get("provider_type", "openai"),
                "model_override": u["model_override"], "priority": u["priority"],
                "weight": u["weight"], "enabled": bool(u["enabled"]),
                "has_token": bool(u["token"]),
            }
            for u in r["upstreams"]
        ]
        out.append(r)
    return out


@router.get("/routes/{rid}/health")
def route_health(rid: int, user: dict = Depends(admin)):
    row = db.db().execute("SELECT * FROM routes WHERE id=?", (rid,)).fetchone()
    if not row:
        raise HTTPException(404, "Endpoint not found.")
    return {
        "strategy": row["strategy"],
        "upstreams": pool.report(config.upstreams(rid)),
    }


def _save_upstreams(route_id: int, items: List[UpstreamIn]):
    keep = []
    for u in items:
        if not u.url.strip():
            continue
        if u.id:
            existing = db.db().execute(
                "SELECT token FROM upstreams WHERE id=? AND route_id=?",
                (u.id, route_id),
            ).fetchone()
            if not existing:
                continue
            token = existing["token"] if u.token is None else db.encrypt(u.token)
            db.db().execute(
                "UPDATE upstreams SET name=?,provider_type=?,url=?,token=?,"
                "model_override=?,priority=?,weight=?,enabled=? WHERE id=?",
                (u.name, u.provider_type, u.url, token, u.model_override,
                 u.priority, max(1, u.weight), 1 if u.enabled else 0, u.id),
            )
            keep.append(u.id)
        else:
            cur = db.db().execute(
                "INSERT INTO upstreams(route_id,name,provider_type,url,token,"
                "model_override,priority,weight,enabled) VALUES(?,?,?,?,?,?,?,?,?)",
                (route_id, u.name, u.provider_type, u.url,
                 db.encrypt(u.token or ""), u.model_override, u.priority,
                 max(1, u.weight), 1 if u.enabled else 0),
            )
            keep.append(cur.lastrowid)
    if keep:
        marks = ",".join("?" * len(keep))
        db.db().execute(
            f"DELETE FROM upstreams WHERE route_id=? AND id NOT IN ({marks})",
            (route_id, *keep),
        )
    else:
        db.db().execute("DELETE FROM upstreams WHERE route_id=?", (route_id,))


@router.post("/routes")
def add_route(body: RouteIn, user: dict = Depends(admin)):
    prefix = _check_prefix(body.prefix)
    if body.strategy not in STRATEGIES:
        raise HTTPException(400, "Unknown strategy.")
    if not body.upstreams:
        raise HTTPException(400, "An endpoint needs at least one provider.")
    try:
        cur = db.db().execute(
            "INSERT INTO routes(prefix,label,enabled,upstream_url,upstream_token,"
            "model_override,mask_roles,entities,use_llm,timeout,strategy,retries) "
            "VALUES(?,?,?,'','','',?,?,?,?,?,?)",
            (prefix, body.label, 1 if body.enabled else 0,
             json.dumps(body.mask_roles), json.dumps(body.entities),
             None if body.use_llm is None else int(body.use_llm),
             body.timeout, body.strategy, max(0, body.retries)),
        )
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "An endpoint with that path already exists.")
    _save_upstreams(cur.lastrowid, body.upstreams)
    db.db().commit()
    db.audit(user["username"], "route_create", prefix)
    return {"ok": True}


@router.put("/routes/{rid}")
def edit_route(rid: int, body: RouteIn, user: dict = Depends(admin)):
    prefix = _check_prefix(body.prefix)
    if body.strategy not in STRATEGIES:
        raise HTTPException(400, "Unknown strategy.")
    if not db.db().execute("SELECT 1 FROM routes WHERE id=?", (rid,)).fetchone():
        raise HTTPException(404, "Endpoint not found.")
    if not body.upstreams:
        raise HTTPException(400, "An endpoint needs at least one provider.")
    db.db().execute(
        "UPDATE routes SET prefix=?,label=?,enabled=?,mask_roles=?,entities=?,"
        "use_llm=?,timeout=?,strategy=?,retries=? WHERE id=?",
        (prefix, body.label, 1 if body.enabled else 0,
         json.dumps(body.mask_roles), json.dumps(body.entities),
         None if body.use_llm is None else int(body.use_llm), body.timeout,
         body.strategy, max(0, body.retries), rid),
    )
    _save_upstreams(rid, body.upstreams)
    db.db().commit()
    db.audit(user["username"], "route_update", prefix)
    return {"ok": True}


@router.delete("/routes/{rid}")
def remove_route(rid: int, user: dict = Depends(admin)):
    db.db().execute("DELETE FROM upstreams WHERE route_id=?", (rid,))
    db.db().execute("DELETE FROM routes WHERE id=?", (rid,))
    db.db().commit()
    db.audit(user["username"], "route_delete", str(rid))
    return {"ok": True}


class UpstreamTest(BaseModel):
    url: str
    provider_type: str = "openai"
    token: Optional[str] = None
    model: str = ""
    upstream_id: Optional[int] = None


@router.post("/upstreams/test")
async def test_upstream(body: UpstreamTest, user: dict = Depends(admin)):
    import httpx

    token = body.token
    if not token and body.upstream_id:
        row = db.db().execute(
            "SELECT token FROM upstreams WHERE id=?", (body.upstream_id,)
        ).fetchone()
        token = db.decrypt(row["token"]) if row else ""
    import net

    try:
        import providers as _prov

        async with net.client(30, body.url) as client:
            r = await client.post(
                f"{body.url.rstrip('/')}/chat/completions",
                headers=_prov.auth_headers(body.provider_type, token or ""),
                json={"model": body.model or "auto:fast", "max_tokens": 5,
                      "messages": [{"role": "user", "content": "reply OK"}]},
            )
        return {"ok": r.status_code == 200, "status": r.status_code,
                "routed_via": r.headers.get("x-routed-via", ""),
                "detail": "" if r.status_code == 200 else r.text[:300]}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "status": 0, "detail": str(exc)}


# ------------------------------------------------------------ diagnostics
class TestText(BaseModel):
    text: str
    use_llm: Optional[bool] = None


@router.post("/test/detect")
async def test_detect(body: TestText, user: dict = Depends(admin)):
    from openai_proxy import analyze_text

    results = await analyze_text(body.text, None, body.use_llm)
    return {
        "count": len(results),
        "results": [
            {"entity_type": r.entity_type, "start": r.start, "end": r.end,
             "score": round(r.score, 3), "text": body.text[r.start : r.end]}
            for r in results
        ],
    }


@router.post("/test/llm")
async def test_llm(user: dict = Depends(admin)):
    import httpx

    cfg = config.llm()
    if not cfg["base_url"]:
        raise HTTPException(400, "No base URL configured.")
    import net

    try:
        async with net.client(30, cfg["base_url"]) as client:
            r = await client.post(
                f"{cfg['base_url']}/chat/completions",
                headers={"Authorization": f"Bearer {cfg['token'] or 'not-needed'}"},
                json={"model": cfg["model"], "max_tokens": 5,
                      "messages": [{"role": "user", "content": "reply OK"}]},
            )
        return {
            "ok": r.status_code == 200,
            "status": r.status_code,
            "routed_via": r.headers.get("x-routed-via", ""),
            "detail": "" if r.status_code == 200 else r.text[:300],
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "status": 0, "detail": str(exc)}


class ProxyTest(BaseModel):
    url: Optional[str] = None


@router.post("/test/proxy")
async def test_proxy(body: ProxyTest, user: dict = Depends(admin)):
    import net

    return await net.check(body.url or None)


# ---------------------------------------------------------- playground
@router.get("/routes/{rid}/models")
async def route_models(rid: int, user: dict = Depends(admin)):
    """Model catalogue from every upstream on a route, merged."""
    import net

    upstreams = config.upstreams(rid)
    if not upstreams:
        raise HTTPException(404, "No providers on that endpoint.")
    seen, out, errors = set(), [], []
    for u in upstreams:
        if not u["enabled"]:
            continue
        token = db.decrypt(u["token"])
        url = f"{u['url'].rstrip('/')}/models"
        try:
            import providers as _prov

            async with net.client(30, u["url"]) as client:
                r = await client.get(
                    url,
                    headers=_prov.auth_headers(
                        u.get("provider_type", "openai"), token or ""
                    ),
                )
                r.raise_for_status()
                for m in r.json().get("data", []):
                    mid = m.get("id")
                    if not mid or mid in seen:
                        continue
                    seen.add(mid)
                    # Model ids arrive in two shapes: bare ("gpt-4o-mini") and
                    # namespaced ("openai/gpt-4o-mini"). Split so the picker can
                    # group by vendor either way.
                    vendor, _, short = mid.partition("/")
                    if not short:
                        vendor, short = (m.get("owned_by") or
                                         u.get("provider_type") or "other"), mid
                    out.append({
                        "id": mid, "vendor": vendor, "short": short,
                        "owned_by": m.get("owned_by", ""),
                        "upstream": u["name"] or u["url"],
                    })
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{u['name'] or u['url']}: {exc}")
    out.sort(key=lambda m: m["id"])
    return {"models": out, "errors": errors}


class PlaygroundRun(BaseModel):
    route_id: int
    model: str = "auto:fast"
    prompt: str
    system: str = ""
    temperature: float = 0.7
    max_tokens: int = 512


@router.post("/playground")
async def playground(body: PlaygroundRun, user: dict = Depends(admin)):
    """Run a prompt through the full pipeline and show every stage.

    The point is to make the masking visible: what you typed, what the model
    actually received, what it replied with, and what comes back out.
    """
    import time

    import net
    from balancer import pool
    from vault import Vault

    route = None
    for r in config.routes():
        if r["id"] == body.route_id:
            route = dict(r)
            break
    if route is None:
        raise HTTPException(404, "Endpoint not found.")
    route["upstreams"] = [
        {**u, "token": db.decrypt(u["token"])} for u in route["upstreams"]
    ]
    if not route["entities"]:
        route["entities"] = config.enabled_entities()

    from openai_proxy import _mask_messages

    vault = Vault()
    messages = []
    if body.system:
        messages.append({"role": "system", "content": body.system})
    messages.append({"role": "user", "content": body.prompt})
    masked = await _mask_messages(messages, vault, route)

    candidates = pool.order(route["upstreams"], route["strategy"])
    if not candidates:
        raise HTTPException(503, "No provider enabled on this endpoint.")

    payload = {
        "model": body.model,
        "messages": masked,
        "temperature": body.temperature,
        "max_tokens": body.max_tokens,
    }

    errors = []
    for upstream in candidates[: max(1, route["retries"] + 1)]:
        url = f"{upstream['url'].rstrip('/')}/chat/completions"
        started = time.monotonic()
        try:
            import providers as _prov

            async with net.client(route["timeout"], upstream["url"]) as client:
                r = await client.post(
                    url,
                    json=payload,
                    headers={
                        **_prov.auth_headers(
                            upstream.get("provider_type", "openai"),
                            upstream["token"] or "",
                        ),
                        "Content-Type": "application/json",
                    },
                )
            if r.status_code >= 500 or r.status_code == 429:
                raise RuntimeError(f"{r.status_code} {r.text[:140]}")
            elapsed = int(1000 * (time.monotonic() - started))
            if r.status_code >= 400:
                return {"ok": False, "error": f"{r.status_code} {r.text[:300]}",
                        "upstream": upstream["name"] or upstream["url"]}
            data = r.json()
            usage = data.get("usage") or {}
            db.record_sample(
                upstream["id"], route["prefix"], elapsed, True,
                usage.get("prompt_tokens", 0) or 0,
                usage.get("completion_tokens", 0) or 0,
                vault.size, body.model,
            )
            raw = (data.get("choices") or [{}])[0].get("message", {}).get(
                "content", ""
            )
            return {
                "ok": True,
                "sent_to_model": [
                    {"role": m["role"], "content": m.get("content", "")}
                    for m in masked
                ],
                "raw_reply": raw,
                "restored_reply": vault.restore(raw),
                "placeholders": [
                    {"token": t, "value": v} for t, v in vault.to_real.items()
                ],
                "masked_count": vault.size,
                "upstream": upstream["name"] or upstream["url"],
                "model": data.get("model", body.model),
                "routed_via": r.headers.get("x-routed-via", ""),
                "latency_ms": elapsed,
                "usage": data.get("usage", {}),
            }
        except Exception as exc:  # noqa: BLE001
            pool.record_failure(upstream["id"], str(exc))
            errors.append(f"{upstream['name'] or upstream['url']}: {exc}")
    return {"ok": False, "error": "Every upstream failed", "attempts": errors}


@router.get("/providers")
def provider_catalogue(user: dict = Depends(admin)):
    import providers

    return providers.catalogue()


# ---------------------------------------------------------------- packs
@router.get("/packs")
def list_packs(user: dict = Depends(admin)):
    return config.packs()


class PackToggle(BaseModel):
    key: str
    enabled: bool


@router.put("/packs")
def set_pack(body: PackToggle, user: dict = Depends(admin)):
    """Enabling a pack switches on the patterns that shipped with it, and
    leaves anything you edited or added yourself alone."""
    db.db().execute(
        "INSERT INTO packs(key,enabled) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET enabled=excluded.enabled",
        (body.key, 1 if body.enabled else 0),
    )
    db.db().execute(
        "UPDATE patterns SET enabled=? WHERE pack=? AND builtin=1",
        (1 if body.enabled else 0, body.key),
    )
    # Presidio's own US and UK recognizers always load, so the pack has to
    # gate the entity as well or turning it off changes nothing.
    from patterns import pack_entities

    for entity in pack_entities(body.key):
        db.db().execute(
            "INSERT INTO entity_toggles(entity,enabled) VALUES(?,?) "
            "ON CONFLICT(entity) DO UPDATE SET enabled=excluded.enabled",
            (entity, 1 if body.enabled else 0),
        )
    db.db().commit()
    config.reload()
    db.audit(user["username"], "pack_toggle", f"{body.key}={body.enabled}")
    return {"ok": True}


# ------------------------------------------------------------ analytics
def _percentile(values, pct):
    if not values:
        return 0
    values = sorted(values)
    k = max(0, min(len(values) - 1, int(round((pct / 100) * (len(values) - 1)))))
    return values[k]


@router.get("/analytics")
def analytics(user: dict = Depends(admin)):
    """Latency distribution and token use per provider.

    Percentiles come from the stored samples rather than a running mean: an
    average hides the slow tail, which is the part that actually hurts.
    """
    names = {}
    for r in config.routes():
        for u in r["upstreams"]:
            names[u["id"]] = {"name": u["name"] or u["url"],
                              "provider_type": u.get("provider_type", "openai"),
                              "route": r["prefix"]}
    rows = db.db().execute(
        "SELECT upstream_id, ms, ok, tokens_in, tokens_out, masked FROM samples"
    ).fetchall()
    grouped = {}
    for row in rows:
        g = grouped.setdefault(row["upstream_id"], {
            "ms": [], "requests": 0, "errors": 0,
            "tokens_in": 0, "tokens_out": 0, "masked": 0,
        })
        g["requests"] += 1
        g["errors"] += 0 if row["ok"] else 1
        g["tokens_in"] += row["tokens_in"]
        g["tokens_out"] += row["tokens_out"]
        g["masked"] += row["masked"]
        if row["ok"]:
            g["ms"].append(row["ms"])
    out = []
    for uid, g in grouped.items():
        meta = names.get(uid, {"name": f"removed #{uid}", "provider_type": "",
                               "route": ""})
        out.append({
            "upstream_id": uid, **meta,
            "requests": g["requests"], "errors": g["errors"],
            "p50": _percentile(g["ms"], 50),
            "p95": _percentile(g["ms"], 95),
            "max": max(g["ms"]) if g["ms"] else 0,
            "tokens_in": g["tokens_in"], "tokens_out": g["tokens_out"],
            "masked": g["masked"],
        })
    out.sort(key=lambda x: -x["requests"])
    return {"providers": out, "samples": len(rows)}


# ------------------------------------------------- AI pattern generation
class PatternDraft(BaseModel):
    description: str
    examples: str = ""


GEN_PROMPT = """You write Python regular expressions that detect one kind of
identifier in free text. Return ONLY a JSON object, no fences, no commentary:

{"entity": "UPPER_SNAKE_NAME", "name": "Short human name",
 "regex": "...", "score": 0.6, "context": ["word", "word"],
 "samples": ["a line containing a valid one", "a line that must NOT match"]}

Rules:
- Python `re` syntax. Escape backslashes correctly for JSON.
- Anchor with \\b so it does not match inside longer strings.
- NEVER use nested quantifiers such as (a+)+ or (\\d*)* - they hang the engine.
- Prefer a precise character class over .* or .+
- score: 0.8 for a distinctive shape, 0.5 for moderate, 0.2 for bare digits
  that need surrounding words to be believable.
- context: lower-case words that appear near this identifier in real documents.
- samples: two or three realistic lines, at least one that must not match."""


@router.post("/patterns/generate")
async def generate_pattern(body: PatternDraft, user: dict = Depends(admin)):
    import json as _json

    import httpx

    import net

    cfg = config.llm()
    if not cfg["base_url"]:
        raise HTTPException(400, "Configure the detection model first.")
    ask = f"Identifier to detect: {body.description}"
    if body.examples:
        ask += f"\nReal examples:\n{body.examples}"
    try:
        async with net.client(cfg["timeout"], cfg["base_url"]) as client:
            r = await client.post(
                f"{cfg['base_url']}/chat/completions",
                headers={"Authorization": f"Bearer {cfg['token'] or 'none'}"},
                json={
                    "model": cfg["model"], "temperature": 0,
                    "messages": [
                        {"role": "system", "content": GEN_PROMPT},
                        {"role": "user", "content": ask},
                    ],
                },
            )
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Model call failed: {exc}")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, str(exc))

    content = re.sub(r"^```(?:json)?|```$", "", content.strip(), flags=re.M)
    start, end = content.find("{"), content.rfind("}")
    if start == -1 or end == -1:
        raise HTTPException(422, "The model did not return usable JSON.")
    try:
        draft = _json.loads(content[start : end + 1])
    except ValueError:
        raise HTTPException(422, "The model did not return usable JSON.")

    regex = str(draft.get("regex", ""))
    # A generated pattern goes through exactly the same gate as a typed one.
    problem = regex_problem(regex)
    if problem:
        raise HTTPException(422, f"The model produced an unusable pattern: {problem}")

    samples = draft.get("samples") or []
    if isinstance(samples, str):
        samples = [samples]
    return {
        "entity": re.sub(r"[^A-Z0-9_]", "", str(draft.get("entity", "")).upper())[:40],
        "name": str(draft.get("name", ""))[:60],
        "regex": regex,
        "score": max(0.0, min(1.0, float(draft.get("score", 0.5)))),
        "context": [str(c).lower()[:40] for c in (draft.get("context") or [])][:12],
        "samples": [str(x)[:300] for x in samples][:4],
    }


@router.get("/stats")
def stats(user: dict = Depends(admin)):
    rows = db.db().execute(
        "SELECT day, hour, route, requests, masked, errors FROM stats "
        "ORDER BY day DESC, hour DESC LIMIT 48"
    ).fetchall()
    totals = db.db().execute(
        "SELECT COALESCE(SUM(requests),0) requests, COALESCE(SUM(masked),0) masked, "
        "COALESCE(SUM(errors),0) errors FROM stats"
    ).fetchone()
    return {
        "totals": dict(totals),
        "recent": [dict(r) for r in rows],
        "engine_version": config.version,
        "routes": len(config.routes()),
    }


# ------------------------------------------------- request inspection
@router.get("/captures")
def list_captures(user: dict = Depends(admin)):
    db.prune_captures()
    rows = db.db().execute(
        "SELECT id, ts, route, provider, model, status, ms, masked, tokens_in, "
        "tokens_out, key_name FROM captures ORDER BY id DESC LIMIT 200"
    ).fetchall()
    return {
        "enabled": db.capture_enabled(),
        "days": db.get_setting("capture_days", "1"),
        "limit": db.get_setting("capture_limit", "200"),
        "audit_days": db.get_setting("audit_days", "90"),
        "audit_limit": db.get_setting("audit_limit", "5000"),
        "captures": [dict(r) for r in rows],
    }


@router.get("/captures/{cid}")
def read_capture(cid: int, user: dict = Depends(admin)):
    """Decrypt one captured request. This returns unmasked personal data."""
    row = db.db().execute("SELECT * FROM captures WHERE id=?", (cid,)).fetchone()
    if not row:
        raise HTTPException(404, "That request is no longer stored.")

    def dec(field):
        raw = db.decrypt(row[field]) if row[field] else ""
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return raw

    db.audit(user["username"], "capture_view", f"request {cid}")
    return {
        **{k: row[k] for k in ("id", "ts", "route", "provider", "model",
                               "status", "ms", "masked", "tokens_in",
                               "tokens_out", "key_name")},
        "req_raw": dec("req_raw"),
        "req_masked": dec("req_masked"),
        "resp_raw": dec("resp_raw"),
        "resp_restored": dec("resp_restored"),
        "placeholders": dec("placeholders") or [],
    }


@router.delete("/captures")
def purge_captures(user: dict = Depends(admin)):
    n = db.purge_captures()
    db.audit(user["username"], "capture_purge", f"{n} requests")
    return {"ok": True, "deleted": n}


@router.get("/audit")
def audit_log(user: dict = Depends(admin)):
    db.prune_audit()
    rows = db.db().execute(
        "SELECT ts, actor, action, detail FROM audit ORDER BY id DESC LIMIT 300"
    ).fetchall()
    return {
        "days": db.get_setting("audit_days", "90"),
        "limit": db.get_setting("audit_limit", "5000"),
        "total": db.db().execute("SELECT COUNT(*) c FROM audit").fetchone()["c"],
        "entries": [dict(r) for r in rows],
    }