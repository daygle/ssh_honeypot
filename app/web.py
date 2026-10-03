"""Dashboard + API served alongside the honeypot."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import config, db, honeypot

log = logging.getLogger("daygle.web")

templates = Environment(
    loader=FileSystemLoader(Path(__file__).resolve().parent / "templates"),
    autoescape=select_autoescape(["html", "xml"]),
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
    yield
    await honeypot.stop(acceptor)


app = FastAPI(title="Daygle SSH Honeypot", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    html = templates.get_template("dashboard.html").render(
        stats=db.get_summary(),
        honeypot_port=config.HONEYPOT_PORT,
    )
    return HTMLResponse(html)


@app.get("/api/stats")
def api_stats() -> dict[str, Any]:
    return db.get_summary()


@app.get("/api/ips")
def api_ips() -> list[dict[str, Any]]:
    return db.get_ip_rows()


@app.get("/ssh-blocklist.txt")
def blocklist() -> PlainTextResponse:
    return PlainTextResponse(db.blocklist_text(), media_type="text/plain")


@app.get("/export.csv")
def export_csv() -> Response:
    return Response(
        db.events_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="daygle-ssh-honeypot-events.csv"'},
    )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
