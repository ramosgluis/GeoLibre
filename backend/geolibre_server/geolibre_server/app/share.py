"""Self-hosted GeoLibre Share API and administration portal."""

from __future__ import annotations

import html
import json
import os
import sqlite3
import time
from collections import defaultdict, deque
from typing import Any
from urllib.parse import parse_qs, quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .share_store import ShareStore, slugify

router = APIRouter(prefix="/share", tags=["share"])
SESSION_COOKIE = "geolibre_share_session"
MAX_PROJECT_BYTES = 25 * 1024 * 1024
SESSION_SECONDS = 12 * 60 * 60
_login_attempts: dict[str, deque[float]] = defaultdict(deque)


def store() -> ShareStore:
    return ShareStore()


def public_url() -> str:
    return os.environ.get(
        "GEOLIBRE_SHARE_PUBLIC_URL", "http://localhost:5173/share"
    ).rstrip("/")


def bearer(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    return authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""


def api_user(request: Request):
    user = store().authenticate_token(bearer(request))
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired API token")
    return user


def session_user(request: Request):
    value = request.cookies.get(SESSION_COOKIE, "")
    return store().session_user(value, int(time.time())) if value else None


async def form_data(request: Request) -> dict[str, str]:
    body = await request.body()
    if len(body) > 64 * 1024:
        raise HTTPException(status_code=413, detail="Form too large")
    parsed = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
    return {key: values[-1] for key, values in parsed.items()}


def require_csrf(form: dict[str, str], expected: str) -> None:
    if not expected or form.get("csrf") != expected:
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def project_json(row: Any) -> dict[str, Any]:
    base = public_url()
    username = row["username"]
    slug = row["slug"]
    raw = f"{base}/{quote(username)}/{quote(slug)}.geolibre.json"
    page = f"{base}/{quote(username)}/{quote(slug)}"
    viewer_base = base.removesuffix("/share")
    return {
        "id": str(row["id"]),
        "username": username,
        "slug": slug,
        "title": row["title"],
        "description": row["description"],
        "visibility": row["visibility"],
        "thumbnailUrl": None,
        "views": row["views"],
        "forkCount": 0,
        "versionCount": row["version_count"],
        "featured": bool(row["featured"]),
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
        "tags": [],
        "rawJsonUrl": raw,
        "projectUrl": page,
        "viewerUrl": f"{viewer_base}/?url={quote(raw, safe='')}",
    }


def page(title: str, body: str) -> HTMLResponse:
    content = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{html.escape(title)} · GeoLibre Share</title>
<style>
:root{{--bg:#f5f7f4;--card:#fff;--ink:#17211b;--muted:#627066;--green:#176b47;--line:#dce4de}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,sans-serif}}
main{{max-width:760px;margin:7vh auto;padding:24px}}header{{display:flex;justify-content:space-between;align-items:center}}
.brand{{color:var(--green);font-weight:800;text-decoration:none;font-size:1.2rem}}.card{{background:var(--card);
border:1px solid var(--line);border-radius:16px;padding:28px;margin-top:22px;box-shadow:0 12px 35px #163e2410}}
label{{display:block;font-weight:650;margin:14px 0 5px}}input,select{{width:100%;padding:11px;border:1px solid #b8c5bc;border-radius:8px}}
button,.button{{display:inline-block;border:0;border-radius:8px;padding:11px 16px;background:var(--green);color:white;
font-weight:700;text-decoration:none;cursor:pointer;margin-top:16px}}button.danger{{background:#9d2d2d}}code{{overflow-wrap:anywhere}}
.muted{{color:var(--muted)}}.token{{background:#edf6f0;border:1px solid #bcd7c5;padding:14px;border-radius:8px}}
table{{width:100%;border-collapse:collapse}}td,th{{padding:10px 4px;border-bottom:1px solid var(--line);text-align:left}}
</style></head><body><main><header><a class="brand" href="{public_url()}/settings">GeoLibre Share local</a>
<a href="{public_url().removesuffix('/share')}">Abrir mapa</a></header>{body}</main></body></html>"""
    response = HTMLResponse(content)
    response.headers.update(
        {
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
        }
    )
    return response


@router.get("/health")
def share_health():
    store()
    return {"status": "ok"}


@router.get("", include_in_schema=False)
@router.get("/", include_in_schema=False)
def share_home():
    return RedirectResponse(f"{public_url()}/settings", status_code=302)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = ""):
    if session_user(request):
        return RedirectResponse(f"{public_url()}/settings", status_code=302)
    error_html = '<p style="color:#9d2d2d">Usuario o contraseña incorrectos.</p>' if error else ""
    return page(
        "Iniciar sesión",
        f"""<section class="card"><h1>Administrar Share</h1>{error_html}
<p class="muted">Usuarios, tokens API y proyectos permanecen en este servidor.</p>
<form method="post" action="{public_url()}/login">
<label>Usuario</label><input name="username" autocomplete="username" required>
<label>Contraseña</label><input type="password" name="password" autocomplete="current-password" required>
<button>Iniciar sesión</button></form></section>""",
    )


@router.post("/login")
async def login(request: Request):
    address = request.client.host if request.client else "unknown"
    attempts = _login_attempts[address]
    now = time.monotonic()
    while attempts and attempts[0] < now - 900:
        attempts.popleft()
    if len(attempts) >= 10:
        raise HTTPException(status_code=429, detail="Too many login attempts")
    form = await form_data(request)
    user = store().authenticate_password(form.get("username", ""), form.get("password", ""))
    if not user:
        attempts.append(now)
        return RedirectResponse(f"{public_url()}/login?error=1", status_code=303)
    attempts.clear()
    session, _ = store().create_session(user["id"], int(time.time()) + SESSION_SECONDS)
    response = RedirectResponse(f"{public_url()}/settings", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        session,
        max_age=SESSION_SECONDS,
        secure=public_url().startswith("https://"),
        httponly=True,
        samesite="strict",
        path="/share",
    )
    return response


@router.post("/logout")
async def logout(request: Request):
    current = session_user(request)
    form = await form_data(request)
    if current:
        _, csrf = current
        require_csrf(form, csrf)
        store().delete_session(request.cookies.get(SESSION_COOKIE, ""))
    response = RedirectResponse(f"{public_url()}/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/share")
    return response


@router.get("/settings", response_class=HTMLResponse)
def settings(request: Request, token: str = ""):
    current = session_user(request)
    if not current:
        return RedirectResponse(f"{public_url()}/login", status_code=302)
    user, csrf = current
    token_notice = (
        f'<div class="token"><strong>Copie ahora su token; no volverá a mostrarse:</strong><br><code>{html.escape(token)}</code></div>'
        if token
        else ""
    )
    token_rows = "".join(
        f"""<tr><td>{html.escape(row["name"])}</td><td><code>{html.escape(row["token_prefix"])}…</code></td>
<td>{html.escape(row["last_used_at"] or "Nunca")}</td><td><form method="post" action="{public_url()}/tokens/{row["id"]}/revoke">
<input type="hidden" name="csrf" value="{csrf}"><button class="danger">Revocar</button></form></td></tr>"""
        for row in store().list_tokens(user["id"])
    )
    admin = ""
    if user["is_admin"]:
        admin = f"""<section class="card"><h2>Crear usuario</h2>
<form method="post" action="{public_url()}/users">
<input type="hidden" name="csrf" value="{csrf}">
<label>Usuario</label><input name="username" required minlength="3" maxlength="32">
<label>Contraseña inicial</label><input type="password" name="password" required minlength="12">
<label><input style="width:auto" type="checkbox" name="admin" value="1"> Administrador</label>
<button>Crear usuario</button></form></section>"""
    return page(
        "Configuración",
        f"""<section class="card"><h1>Hola, {html.escape(user["username"])}</h1>
<p class="muted">Este Share es completamente local en geolibre.mapptech.com.co.</p>{token_notice}
<h2>Tokens API</h2><p>GeoLibre usa un token para publicar y abrir sus proyectos privados.</p>
<form method="post" action="{public_url()}/tokens"><input type="hidden" name="csrf" value="{csrf}">
<label>Nombre del token</label><input name="name" value="GeoLibre web" maxlength="80"><button>Crear token</button></form>
<table><thead><tr><th>Nombre</th><th>Prefijo</th><th>Último uso</th><th></th></tr></thead><tbody>{token_rows}</tbody></table>
<h2>Cambiar contraseña</h2><form method="post" action="{public_url()}/password">
<input type="hidden" name="csrf" value="{csrf}"><label>Nueva contraseña</label>
<input type="password" name="password" required minlength="12"><button>Cambiar contraseña</button></form>
<form method="post" action="{public_url()}/logout"><input type="hidden" name="csrf" value="{csrf}"><button class="danger">Cerrar sesión</button></form>
</section>{admin}""",
    )


@router.post("/tokens")
async def create_token(request: Request):
    current = session_user(request)
    if not current:
        return RedirectResponse(f"{public_url()}/login", status_code=302)
    user, csrf = current
    form = await form_data(request)
    require_csrf(form, csrf)
    token = store().create_token(user["id"], form.get("name", "GeoLibre"))
    # Render the one-time value directly. Putting it in a redirect query string
    # would expose it to browser history and reverse-proxy access logs.
    return settings(request, token=token)


@router.post("/tokens/{token_id}/revoke")
async def revoke_token(token_id: int, request: Request):
    current = session_user(request)
    if not current:
        return RedirectResponse(f"{public_url()}/login", status_code=302)
    user, csrf = current
    form = await form_data(request)
    require_csrf(form, csrf)
    store().revoke_token(user["id"], token_id)
    return RedirectResponse(f"{public_url()}/settings", status_code=303)


@router.post("/password")
async def change_password(request: Request):
    current = session_user(request)
    if not current:
        return RedirectResponse(f"{public_url()}/login", status_code=302)
    user, csrf = current
    form = await form_data(request)
    require_csrf(form, csrf)
    try:
        store().change_password(user["id"], form.get("password", ""))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    response = RedirectResponse(f"{public_url()}/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/share")
    return response


@router.post("/users")
async def create_user(request: Request):
    current = session_user(request)
    if not current or not current[0]["is_admin"]:
        raise HTTPException(status_code=403, detail="Administrator required")
    user, csrf = current
    form = await form_data(request)
    require_csrf(form, csrf)
    try:
        store().create_user(
            form.get("username", ""), form.get("password", ""), admin=form.get("admin") == "1"
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Username already exists") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse(f"{public_url()}/settings", status_code=303)


@router.post("/api/projects")
async def upload_project(request: Request):
    user = api_user(request)
    body = await request.body()
    if len(body) > MAX_PROJECT_BYTES:
        raise HTTPException(status_code=413, detail="Project is too large")
    try:
        payload = json.loads(body)
        content = payload["content"]
        project = json.loads(content)
    except (json.JSONDecodeError, KeyError, TypeError):
        return JSONResponse({"error": "Invalid GeoLibre project JSON."}, status_code=400)
    if (
        not isinstance(content, str)
        or not isinstance(project, dict)
        or "version" not in project
        or "mapView" not in project
    ):
        return JSONResponse({"error": "Invalid GeoLibre project JSON."}, status_code=400)
    visibility = payload.get("visibility", "unlisted")
    if visibility not in {"public", "unlisted", "private"}:
        return JSONResponse({"error": "Invalid project visibility."}, status_code=400)
    title = str(project.get("name") or payload.get("filename") or "Proyecto").strip()[:100]
    title = title or "Proyecto"
    slug = slugify(str(payload.get("filename") or title))
    row = store().upsert_project(user["id"], slug, title, visibility, content)
    result = project_json({**dict(row), "username": user["username"]})
    return {"project": result}


@router.get("/api/projects")
def list_projects(limit: int = 20, offset: int = 0, featured: bool = False):
    limit = min(max(limit, 1), 100)
    offset = max(offset, 0)
    return {"projects": [project_json(row) for row in store().list_public(limit, offset, featured)]}


@router.get("/api/users/me")
def current_api_user(request: Request):
    user = api_user(request)
    return {"user": {"username": user["username"]}}


@router.get("/api/users/{username}/projects")
def user_projects(username: str, request: Request):
    user = api_user(request)
    if user["username"].lower() != username.lower() and not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    target = store().get_user_by_name(username)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    return {"projects": [project_json(row) for row in store().list_user_projects(target["id"])]}


@router.get("/{username}/{slug}.geolibre.json")
def raw_project(username: str, slug: str, request: Request):
    row = store().find_project(username, slug)
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")
    if row["visibility"] == "private":
        user = api_user(request)
        if user["id"] != row["user_id"] and not user["is_admin"]:
            raise HTTPException(status_code=403, detail="Not allowed")
    store().increment_views(row["id"])
    response = Response(row["content"], media_type="application/json")
    response.headers["Cache-Control"] = "private, no-store" if row["visibility"] == "private" else "public, max-age=60"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if row["visibility"] != "private":
        response.headers["Access-Control-Allow-Origin"] = "*"
    return response


@router.get("/{username}/{slug}", response_class=HTMLResponse)
def project_page(username: str, slug: str):
    row = store().find_project(username, slug)
    if not row or row["visibility"] == "private":
        raise HTTPException(status_code=404, detail="Project not found")
    project = project_json(row)
    return page(
        row["title"],
        f"""<section class="card"><p class="muted">{html.escape(username)} · {html.escape(row["visibility"])}</p>
<h1>{html.escape(row["title"])}</h1><p>{html.escape(row["description"])}</p>
<a class="button" href="{html.escape(project["viewerUrl"])}">Abrir mapa en GeoLibre</a>
<p><a href="{html.escape(project["rawJsonUrl"])}">Descargar proyecto .geolibre.json</a></p></section>""",
    )
