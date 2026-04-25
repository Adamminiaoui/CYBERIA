from __future__ import annotations

import sys
import threading
from pathlib import Path

from fastapi import FastAPI, Query


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from database.db import (
    get_all_indicators,
    get_refresh_status,
    initialize_database,
    refresh_live_feeds,
    search_indicators,
)


app = FastAPI(title="CyberAI Threat Intelligence API", version="1.0.0")
stop_event = threading.Event()


def refresh_worker() -> None:
    while not stop_event.is_set():
        try:
            refresh_live_feeds(per_feed_limit=100)
        except Exception:
            pass
        stop_event.wait(timeout=900)


@app.on_event("startup")
def startup_event() -> None:
    initialize_database()
    refresh_live_feeds(per_feed_limit=100)
    threading.Thread(target=refresh_worker, daemon=True).start()


@app.on_event("shutdown")
def shutdown_event() -> None:
    stop_event.set()


@app.get("/threats")
def read_threats() -> list[dict]:
    return get_all_indicators()


@app.get("/search")
def search_threats(value: str = Query(..., min_length=1)) -> list[dict]:
    return search_indicators(value)


@app.get("/refresh-status")
def read_refresh_status() -> list[dict]:
    return get_refresh_status()


@app.post("/refresh")
def refresh_threats() -> dict[str, object]:
    return refresh_live_feeds(per_feed_limit=100)
