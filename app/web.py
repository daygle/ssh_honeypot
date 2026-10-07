"""Dashboard + API served alongside the honeypot."""

from __future__ import annotations

import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
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


def admin_enabled() -> bool:
    """True when admin credentials are configured (endpoints are live)."""
    return bool(config.WEB_ADMIN_USER and config.WEB_ADMIN_PASS)


def admin_auth(request: Request) -> bool:
    """Return True when the request presents valid admin basic-auth credentials.

    Requires ``admin_enabled()`` to be True; otherwise the caller should treat
    the endpoint as disabled (404).
    """
    if not admin_enabled():
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
    user_ok = secrets.compare_digest(user.encode("utf-8"), config.WEB_ADMIN_USER.encode("utf-8"))
    pass_ok = secrets.compare_digest(password.encode("utf-8"), config.WEB_ADMIN_PASS.encode("utf-8"))
    return user_ok and pass_ok


def dashboard_auth_error() -> HTMLResponse:
    """Challenge the browser for configured dashboard credentials."""
    return HTMLResponse(
        "<h1>Authentication required</h1><p>Sign in with the configured dashboard account.</p>",
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
    """Configured deployments protect dashboard data; empty credentials keep public mode."""
    return admin_enabled() and not admin_auth(request)


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


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    if dashboard_requires_auth(request):
        return dashboard_auth_error()
    nonce = secrets.token_urlsafe(16)
    stats = db.get_summary()
    retention = {
        "enabled": config.RETENTION_HOURS > 0,
        "hours": config.RETENTION_HOURS,
        "older_than": db.count_events_older_than(config.RETENTION_HOURS) if config.RETENTION_HOURS > 0 else 0,
        "admin_enabled": bool(config.WEB_ADMIN_USER and config.WEB_ADMIN_PASS),
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
    if dashboard_requires_auth(request):
        return api_auth_error()
    return db.get_summary()


@app.get("/api/ips")
def api_ips(request: Request) -> Any:
    if dashboard_requires_auth(request):
        return api_auth_error()
    return db.get_ip_rows()


@app.get("/ssh-blocklist.txt")
def blocklist(request: Request) -> Any:
    if dashboard_requires_auth(request):
        return api_auth_error()
    return PlainTextResponse(db.blocklist_text())


@app.delete("/api/events")
def admin_purge(request: Request) -> dict[str, Any]:
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
def admin_delete_event(request: Request, event_id: int) -> dict[str, Any]:
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
