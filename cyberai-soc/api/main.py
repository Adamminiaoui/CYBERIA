from __future__ import annotations

import sys
import threading
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, Query
from fastapi.responses import PlainTextResponse


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from database.db import (
    get_all_indicators,
    get_indicators_dataframe,
    get_refresh_status,
    initialize_database,
    refresh_live_feeds,
    search_indicators,
)
from database.correlation import correlate_observables
from database.modeling import (
    build_soc_narrative,
    detect_workplace_anomalies,
    forecast_threat_trends,
    score_correlations,
)
from database.mongo_bridge import load_mongo_context


app = FastAPI(title="CyberAI Threat Intelligence API", version="1.0.0")
stop_event = threading.Event()


def refresh_worker() -> None:
    while not stop_event.is_set():
        try:
            refresh_live_feeds(per_feed_limit=100)
        except Exception:
            pass
        stop_event.wait(timeout=900)


def dataframe_records(frame: pd.DataFrame) -> list[dict]:
    if frame.empty:
        return []
    records = frame.astype(object).where(pd.notna(frame), None).to_dict(orient="records")
    for record in records:
        for key, value in list(record.items()):
            if hasattr(value, "isoformat"):
                record[key] = value.isoformat()
    return records


def normalized_sqlite_frame() -> pd.DataFrame:
    frame = get_indicators_dataframe()
    if frame.empty:
        return pd.DataFrame(
            columns=[
                "indicator_type",
                "indicator_value",
                "source",
                "threat_type",
                "confidence",
                "severity",
                "first_seen",
                "last_seen",
                "collection",
                "tags",
            ]
        )
    normalized = frame[
        [
            "indicator_type",
            "indicator_value",
            "source",
            "threat_type",
            "confidence",
            "severity",
            "first_seen",
            "last_seen",
        ]
    ].copy()
    normalized["collection"] = "sqlite_global_feeds"
    normalized["tags"] = ""
    return normalized


def build_ai_context() -> dict[str, object]:
    mongo_context = load_mongo_context()
    combined_global = pd.concat(
        [normalized_sqlite_frame(), mongo_context["global_indicators"]],
        ignore_index=True,
    )
    if not combined_global.empty:
        combined_global = combined_global.drop_duplicates(subset=["indicator_type", "indicator_value", "source"])
    workspace = mongo_context["workspace_observables"]
    correlations = correlate_observables(combined_global, workspace)
    scored = score_correlations(correlations)
    anomalies = detect_workplace_anomalies(workspace)
    trends = forecast_threat_trends(combined_global)
    narrative = build_soc_narrative(scored, anomalies, trends)
    return {
        "mongo_status": mongo_context["status"],
        "combined_global": combined_global,
        "workspace_observables": workspace,
        "correlations": correlations,
        "scored_correlations": scored,
        "anomalies": anomalies,
        "trends": trends,
        "narrative": narrative,
    }


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


@app.get("/mongo-status")
def read_mongo_status() -> dict[str, object]:
    return load_mongo_context()["status"]


@app.get("/correlations")
def read_correlations() -> list[dict]:
    return dataframe_records(build_ai_context()["scored_correlations"])


@app.get("/model-summary")
def read_model_summary() -> dict[str, object]:
    context = build_ai_context()
    return {
        "narrative": context["narrative"],
        "global_indicators": len(context["combined_global"]),
        "workspace_observables": len(context["workspace_observables"]),
        "correlations": len(context["scored_correlations"]),
        "anomaly_windows": int(context["anomalies"]["is_anomaly"].sum())
        if not context["anomalies"].empty and "is_anomaly" in context["anomalies"]
        else 0,
        "rising_threats": dataframe_records(context["trends"][context["trends"]["trend_signal"] == "rising"]),
    }


@app.get("/export/global.csv", response_class=PlainTextResponse)
def export_global_csv() -> str:
    context = build_ai_context()
    frame = context["combined_global"]
    if frame.empty:
        return ""
    export_cols = [
        "indicator_type",
        "indicator_value",
        "source",
        "threat_type",
        "confidence",
        "severity",
        "first_seen",
        "last_seen",
        "collection",
        "tags",
    ]
    available = [c for c in export_cols if c in frame.columns]
    return frame[available].to_csv(index=False)


@app.get("/export/correlations.csv", response_class=PlainTextResponse)
def export_correlations_csv() -> str:
    scored = build_ai_context()["scored_correlations"]
    if scored.empty:
        return ""
    return scored.to_csv(index=False)


@app.get("/export/anomalies.csv", response_class=PlainTextResponse)
def export_anomalies_csv() -> str:
    anomalies = build_ai_context()["anomalies"]
    if anomalies.empty:
        return ""
    return anomalies.to_csv(index=False)


@app.get("/export/trends.csv", response_class=PlainTextResponse)
def export_trends_csv() -> str:
    trends = build_ai_context()["trends"]
    if trends.empty:
        return ""
    return trends.to_csv(index=False)
