"""Entry point: `python -m app`."""

import uvicorn

from . import config

if __name__ == "__main__":
    uvicorn.run(
        "app.web:app",
        host=config.WEB_HOST,
        port=config.WEB_PORT,
        log_level="info",
        server_header=False,
    )
