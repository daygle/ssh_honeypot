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

from . import config, db, honeypot

log = logging.getLogger("daygle.web")

templates = Environment(
    loader=FileSystemLoader(Path(__file__).resolve().parent / "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)

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
def dashboard() -> HTMLResponse:
    nonce = secrets.token_urlsafe(16)
    html = templates.get_template("dashboard.html").render(
        stats=db.get_summary(),
        honeypot_port=config.HONEYPOT_PORT,
        csp_nonce=nonce,
    )
    return HTMLResponse(html, headers={"Content-Security-Policy": CSP_TEMPLATE.format(nonce=nonce)})


@app.get("/api/stats")
def api_stats() -> dict[str, Any]:
    return db.get_summary()


@app.get("/api/ips")
def api_ips() -> list[dict[str, Any]]:
    return db.get_ip_rows()


@app.get("/ssh-blocklist.txt")
def blocklist() -> PlainTextResponse:
    return PlainTextResponse(db.blocklist_text())


@app.get("/export.csv")
def export_csv() -> StreamingResponse:
    return StreamingResponse(
        db.iter_events_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="daygle-ssh-honeypot-events.csv"'},
    )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
