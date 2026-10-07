"""Dashboard + API served alongside the honeypot."""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable
from urllib.parse import parse_qs, urlencode

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from datetime import datetime, timezone

from . import config, db, honeypot

log = logging.getLogger("daygle.web")

templates = Environment(
    loader=FileSystemLoader(Path(__file__).resolve().parent / "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)


def _jinja_datefmt(ts: str, fmt: str | None = None) -> str:
    """Render an ISO-UTC timestamp string with a strftime-style format.

    The dashboard stores timestamps as ``%Y-%m-%dT%H:%M:%SZ``; this helper
    parses that form and applies the user-facing DATE_FORMAT.
    """
    if not ts:
        return "-"
    try:
        # Accept both the canonical Z form and a bare space form from older rows.
        clean = ts.replace("Z", "").strip()
        dt = datetime.strptime(clean, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return ts
    format = fmt or config.DATE_FORMAT
    return dt.strftime(format)


def _jinja_title(value: str) -> str:
    """Title-case an event label for display (connect -> Connect)."""
    if not value:
        return value
    return value.title()


templates.filters["datefmt"] = _jinja_datefmt
templates.filters["title"] = _jinja_title


PASSWORD_HASH_ITERATIONS = 310_000


def admin_enabled() -> bool:
    """True when environment or first-run admin credentials are configured."""
    return bool(
        (config.WEB_ADMIN_USER and config.WEB_ADMIN_PASS)
        or db.admin_credentials()
    )


def setup_required() -> bool:
    """Fresh databases with no environment-provided admin require initial setup."""
    if config.WEB_ADMIN_USER and config.WEB_ADMIN_PASS:
        return False
    return db.admin_setup_required()


def _admin_credentials() -> tuple[str, str, str | None] | None:
    if config.WEB_ADMIN_USER and config.WEB_ADMIN_PASS:
        return config.WEB_ADMIN_USER, config.WEB_ADMIN_PASS, None
    stored = db.admin_credentials()
    if not stored:
        return None
    return stored["username"], stored["password_hash"], stored["salt"]


def _password_hash(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    ).hex()


def admin_auth(request: Request) -> bool:
    """Return True when the request presents valid admin basic-auth credentials.

    Requires ``admin_enabled()`` to be True; otherwise the caller should treat
    the endpoint as disabled (404).
    """
    credentials = _admin_credentials()
    if not credentials:
        return False
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return False
    import base64
    try:
        decoded = base64.b64decode(auth.split(" ", 1)[1], validate=True).decode("utf-8")
        user, sep, password = decoded.partition(":")
    except Exception:
        return False
    expected_user, expected_password, salt = credentials
    user_ok = secrets.compare_digest(user.encode("utf-8"), expected_user.encode("utf-8"))
    if salt is None:
        pass_ok = secrets.compare_digest(password.encode("utf-8"), expected_password.encode("utf-8"))
    else:
        candidate = _password_hash(password, bytes.fromhex(salt))
        pass_ok = hmac.compare_digest(candidate, expected_password)
    return user_ok and pass_ok


def dashboard_auth_error() -> HTMLResponse:
    """Challenge the browser for configured dashboard credentials."""
    return HTMLResponse(
        "<h1>Authentication required</h1><p>Sign in with your dashboard admin account.</p>",
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="Daygle Dashboard", charset="UTF-8"'},
    )


def api_auth_error() -> Response:
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=401,
        content={"detail": "dashboard authentication required"},
        headers={"WWW-Authenticate": 'Basic realm="Daygle Dashboard", charset="UTF-8"'},
    )


def dashboard_requires_auth(request: Request) -> bool:
    """Configured deployments protect dashboard data; empty legacy installs remain public."""
    return admin_enabled() and not admin_auth(request)


def setup_response() -> RedirectResponse:
    token = db.setup_token()
    location = "/setup"
    if token:
        location += "?" + urlencode({"key": token})
    return RedirectResponse(location, status_code=303, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

# The dashboard renders attacker-supplied strings (usernames, passwords,
# banners); a strict CSP is defence in depth on top of output escaping.
CSP_TEMPLATE = (
    "default-src 'none'; "
    "script-src 'nonce-{nonce}'; "
    "style-src 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    db.init_db()
    if setup_required():
        host = config.WEB_HOST if config.WEB_HOST not in {"0.0.0.0", "::", ""} else "<dashboard-host>"
        log.warning(
            "Initial admin setup required. Open http://%s:%s/setup?key=%s "
            "from a trusted network and keep the link private.",
            host,
            config.WEB_PORT,
            db.setup_token(),
        )
    acceptor = None
    try:
        acceptor = await honeypot.start()
    except OSError as exc:
        # Preview environments cannot bind privileged/decoy ports; the
        # dashboard still runs so the UI is inspectable.
        log.warning("honeypot listener not started (%s) - dashboard only", exc)
    try:
        yield
    finally:
        await honeypot.stop(acceptor)


# The interactive API docs are not part of the dashboard and would load
# third-party assets on an internet-facing host, so they are disabled.
app = FastAPI(
    title="Daygle SSH Honeypot",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.middleware("http")
async def security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


def valid_setup_token(request: Request) -> bool:
    expected = db.setup_token()
    supplied = request.query_params.get("key", "")
    return bool(expected and supplied and secrets.compare_digest(expected, supplied))


@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request) -> Any:
    if not setup_required():
        return RedirectResponse("/", status_code=303)
    if not valid_setup_token(request):
        headers = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}
        return HTMLResponse("This installation requires its first-run setup link.", status_code=404, headers=headers)
    return HTMLResponse(
        templates.get_template("setup.html").render(error=None, setup_key=db.setup_token()),
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"},
    )


@app.post("/setup", response_class=HTMLResponse)
async def setup_admin(request: Request) -> Any:
    if not setup_required():
        return HTMLResponse("Setup has already been completed.", status_code=409, headers={"Cache-Control": "no-store"})
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/x-www-form-urlencoded":
        return HTMLResponse("Invalid setup form.", status_code=415, headers={"Cache-Control": "no-store"})
    body = await request.body()
    if len(body) > 4096:
        return HTMLResponse("Setup form is too large.", status_code=413, headers={"Cache-Control": "no-store"})
    values = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    submitted_token = values.get("setup_key", [""])[0]
    expected_token = db.setup_token()
    if not expected_token or not secrets.compare_digest(expected_token, submitted_token):
        return HTMLResponse("This setup link is invalid or has expired.", status_code=404, headers={"Cache-Control": "no-store"})
    username = values.get("username", [""])[0].strip()
    password = values.get("password", [""])[0]
    confirmation = values.get("password_confirm", [""])[0]
    error = None
    if not username or len(username) > 64 or ":" in username or any(ord(char) < 32 for char in username):
        error = "Choose a username between 1 and 64 characters."
    elif len(password) < 12:
        error = "Choose a password with at least 12 characters."
    elif len(password) > 1024:
        error = "Password must be 1024 characters or fewer."
    elif password != confirmation:
        error = "The password confirmation does not match."
    if error:
        return HTMLResponse(
            templates.get_template("setup.html").render(error=error, setup_key=expected_token),
            status_code=400,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"},
        )

    salt = secrets.token_bytes(16)
    password_hash = _password_hash(password, salt)
    if not db.complete_admin_setup(username, salt.hex(), password_hash, expected_token):
        return HTMLResponse("Setup has already been completed.", status_code=409, headers={"Cache-Control": "no-store"})
    return RedirectResponse("/", status_code=303, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> Any:
    if setup_required():
        return setup_response()
    if dashboard_requires_auth(request):
        return dashboard_auth_error()
    nonce = secrets.token_urlsafe(16)
    stats = db.get_summary()
    if admin_enabled():
        db.ensure_default_retention_days()
    retention = {
        "enabled": db.retention_days() > 0,
        "days": db.retention_days(),
        "older_than": db.count_events_older_than_days(db.retention_days()),
        "admin_enabled": admin_enabled(),
        "hours_legacy": config.RETENTION_HOURS,
    }
    html = templates.get_template("dashboard.html").render(
        stats=stats,
        honeypot_port=config.HONEYPOT_PORT,
        csp_nonce=nonce,
        date_format=config.DATE_FORMAT,
        relative_format=config.RELATIVE_FORMAT,
        retention=retention,
    )
    return HTMLResponse(html, headers={"Content-Security-Policy": CSP_TEMPLATE.format(nonce=nonce)})


@app.get("/api/stats")
def api_stats(request: Request) -> Any:
    if setup_required():
        return setup_response()
    if dashboard_requires_auth(request):
        return api_auth_error()
    return db.get_summary()


@app.get("/api/ips")
def api_ips(request: Request) -> Any:
    if setup_required():
        return setup_response()
    if dashboard_requires_auth(request):
        return api_auth_error()
    return db.get_ip_rows()


@app.get("/ssh-blocklist.txt")
def blocklist(request: Request) -> Any:
    if setup_required():
        return setup_response()
    if dashboard_requires_auth(request):
        return api_auth_error()
    return PlainTextResponse(db.blocklist_text())


@app.delete("/api/events")
def admin_purge(request: Request) -> Any:
    """Admin-only purge: delete events older than N hours and/or for specific IPs.

    Query params:
      older_than_hours  - purge events older than this many hours (whole table).
      ips               - comma-separated list of IPs to purge.

    Returns the counts of rows removed for each action.
    """
    if not admin_enabled():
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=404, content={"detail": "admin endpoints disabled"})
    if not admin_auth(request):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=401, content={"detail": "admin auth required"})

    older_than = request.query_params.get("older_than_hours")
    older_hours: int | None = None
    if older_than is not None:
        try:
            older_hours = int(older_than)
        except ValueError:
            return {"error": "older_than_hours must be an integer"}

    ips_raw = request.query_params.get("ips", "")
    ips = [ip.strip() for ip in ips_raw.split(",") if ip.strip()] if ips_raw else []

    removed_older = db.delete_events_older_than(older_hours) if older_hours else 0
    removed_ips = db.delete_events_for_ips(ips) if ips else 0

    return {
        "removed_older_than_hours": removed_older,
        "older_than_hours": older_hours,
        "removed_ips": removed_ips,
        "ips": ips,
        "total_removed": removed_older + removed_ips,
    }


@app.get("/api/retention")
def api_retention(request: Request) -> Any:
    """Current server-side retention window, persisted in app_settings.

    Returns the active retention_days (0 when not yet configured) and how many
    events would be removed by a purge to that window. Public only when no admin
    has been configured; otherwise admin auth is required.
    """
    if setup_required():
        return setup_response()
    if dashboard_requires_auth(request):
        return api_auth_error()
    days = db.retention_days()
    return {
        "retention_days": days,
        "enabled": days > 0,
        "older_than": db.count_events_older_than_days(days),
    }


@app.put("/api/retention")
async def admin_update_retention(request: Request) -> Any:
    """Admin-only update of the GUI retention window, persisted in app_settings.

    Body (JSON): {"retention_days": <int >= 0>}

    retention_days = 0 disables age-based purging. retention_days >= 1 sets the
    GUI retention window; it does not purge automatically (use /api/events with
    older_than_hours, or the Purge now button, to remove old events).
    """
    if not admin_enabled():
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=404, content={"detail": "admin endpoints disabled"})
    if not admin_auth(request):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=401, content={"detail": "admin auth required"})

    if not request.headers.get("content-type", "").split(";", 1)[0].strip().lower() == "application/json":
        return {"error": "content-type must be application/json"}

    body = await request.body()
    if len(body) > 4096:
        return {"error": "request body is too large"}
    import json
    try:
        data = json.loads(body.decode("utf-8", errors="replace"))
    except ValueError:
        return {"error": "invalid json"}

    raw = data.get("retention_days") if isinstance(data, dict) else None
    if raw is None:
        return {"error": "retention_days is required"}
    try:
        days = int(raw)
    except (TypeError, ValueError):
        return {"error": "retention_days must be an integer"}
    if days < 0:
        return {"error": "retention_days must be >= 0"}
    if days > 0 and days > 9999:
        return {"error": "retention_days must be <= 9999"}

    db.set_retention_days(days)
    return {
        "retention_days": days,
        "enabled": days > 0,
        "older_than": db.count_events_older_than_days(days),
    }


@app.delete("/api/events/all")
def admin_delete_all_events(request: Request) -> Any:
    """Admin-only deletion of the entire event history."""
    if not admin_enabled():
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=404, content={"detail": "admin endpoints disabled"})
    if not admin_auth(request):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=401, content={"detail": "admin auth required"})
    with db._connect() as conn:
        cur = conn.execute("DELETE FROM events")
        deleted = int(cur.rowcount)
    return {"ok": True, "deleted": deleted}


@app.delete("/api/events/{event_id:int}")
def admin_delete_event(request: Request, event_id: int) -> Any:
    """Admin-only delete of a single event by id."""
    if not admin_enabled():
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=404, content={"detail": "admin endpoints disabled"})
    if not admin_auth(request):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=401, content={"detail": "admin auth required"})
    ok = db.delete_event(event_id)
    if not ok:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=404, content={"detail": "event not found"})
    return {"deleted": event_id, "ok": True}


@app.get("/export.csv")
def export_csv(request: Request) -> Any:
    if setup_required():
        return setup_response()
    if dashboard_requires_auth(request):
        return api_auth_error()
    return StreamingResponse(
        db.iter_events_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="daygle-ssh-honeypot-events.csv"'},
    )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
