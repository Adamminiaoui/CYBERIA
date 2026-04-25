from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Iterable, Optional

import pandas as pd

from database.live_feeds import LIVE_FEEDS, fetch_feed_records


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
DB_PATH = BASE_DIR / "threat_intel.db"
SAMPLE_CSV_PATH = DATA_DIR / "sample_threats.csv"


CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS threat_indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_type TEXT NOT NULL,
    indicator_value TEXT NOT NULL UNIQUE,
    threat_type TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence INTEGER NOT NULL CHECK(confidence BETWEEN 0 AND 100),
    severity TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    created_at TEXT NOT NULL
)
"""


CREATE_REFRESH_STATE_SQL = """
CREATE TABLE IF NOT EXISTS refresh_state (
    feed_name TEXT PRIMARY KEY,
    last_refresh_at TEXT,
    last_success_at TEXT,
    status TEXT NOT NULL,
    message TEXT,
    inserted_count INTEGER NOT NULL DEFAULT 0,
    updated_count INTEGER NOT NULL DEFAULT 0,
    total_fetched INTEGER NOT NULL DEFAULT 0
)
"""


UPSERT_SQL = """
INSERT INTO threat_indicators (
    indicator_type,
    indicator_value,
    threat_type,
    source,
    confidence,
    severity,
    first_seen,
    last_seen,
    created_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(indicator_value) DO UPDATE SET
    indicator_type = excluded.indicator_type,
    threat_type = excluded.threat_type,
    source = excluded.source,
    confidence = CASE
        WHEN excluded.confidence > threat_indicators.confidence THEN excluded.confidence
        ELSE threat_indicators.confidence
    END,
    severity = CASE
        WHEN excluded.confidence >= threat_indicators.confidence THEN excluded.severity
        ELSE threat_indicators.severity
    END,
    first_seen = CASE
        WHEN excluded.first_seen < threat_indicators.first_seen THEN excluded.first_seen
        ELSE threat_indicators.first_seen
    END,
    last_seen = CASE
        WHEN excluded.last_seen > threat_indicators.last_seen THEN excluded.last_seen
        ELSE threat_indicators.last_seen
    END
"""


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def get_connection(db_path: Path | str = DB_PATH) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database(
    db_path: Path | str = DB_PATH,
    sample_csv_path: Path | str = SAMPLE_CSV_PATH,
) -> None:
    """Create the SQLite database and seed it from the CSV when empty."""
    with get_connection(db_path) as connection:
        connection.execute(CREATE_TABLE_SQL)
        connection.execute(CREATE_REFRESH_STATE_SQL)
        existing_rows = connection.execute(
            "SELECT COUNT(*) AS total FROM threat_indicators"
        ).fetchone()["total"]

    if existing_rows == 0:
        insert_sample_data(db_path=db_path, sample_csv_path=sample_csv_path)


def insert_sample_data(
    db_path: Path | str = DB_PATH,
    sample_csv_path: Path | str = SAMPLE_CSV_PATH,
) -> int:
    """Load indicators from CSV into SQLite."""
    frame = pd.read_csv(sample_csv_path)
    return upsert_indicators(
        frame.to_dict(orient="records"),
        db_path=db_path,
    )["inserted"]


def upsert_indicators(
    records: Iterable[dict],
    db_path: Path | str = DB_PATH,
) -> dict[str, int]:
    inserted = 0
    updated = 0

    with get_connection(db_path) as connection:
        for record in records:
            exists = connection.execute(
                """
                SELECT id
                FROM threat_indicators
                WHERE indicator_value = ?
                """,
                (record["indicator_value"],),
            ).fetchone()

            connection.execute(
                UPSERT_SQL,
                (
                    record["indicator_type"],
                    record["indicator_value"],
                    record["threat_type"],
                    record["source"],
                    int(record["confidence"]),
                    record["severity"],
                    record["first_seen"],
                    record["last_seen"],
                    record["created_at"],
                ),
            )

            if exists:
                updated += 1
            else:
                inserted += 1

    return {"inserted": inserted, "updated": updated}


def update_refresh_state(
    feed_name: str,
    status: str,
    message: str,
    total_fetched: int,
    inserted_count: int,
    updated_count: int,
    db_path: Path | str = DB_PATH,
) -> None:
    now = utc_now_iso()
    last_success_at = now if status == "success" else None

    with get_connection(db_path) as connection:
        previous = connection.execute(
            """
            SELECT last_success_at
            FROM refresh_state
            WHERE feed_name = ?
            """,
            (feed_name,),
        ).fetchone()

        if status != "success" and previous:
            last_success_at = previous["last_success_at"]

        connection.execute(
            """
            INSERT INTO refresh_state (
                feed_name,
                last_refresh_at,
                last_success_at,
                status,
                message,
                inserted_count,
                updated_count,
                total_fetched
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(feed_name) DO UPDATE SET
                last_refresh_at = excluded.last_refresh_at,
                last_success_at = excluded.last_success_at,
                status = excluded.status,
                message = excluded.message,
                inserted_count = excluded.inserted_count,
                updated_count = excluded.updated_count,
                total_fetched = excluded.total_fetched
            """,
            (
                feed_name,
                now,
                last_success_at,
                status,
                message,
                inserted_count,
                updated_count,
                total_fetched,
            ),
        )


def refresh_live_feeds(
    feed_names: Optional[list[str]] = None,
    per_feed_limit: int = 100,
    db_path: Path | str = DB_PATH,
) -> dict[str, object]:
    initialize_database(db_path=db_path)
    selected_feeds = [
        feed for feed in LIVE_FEEDS if not feed_names or feed.name in feed_names
    ]

    summary: dict[str, object] = {
        "refreshed_at": utc_now_iso(),
        "feeds": [],
        "inserted": 0,
        "updated": 0,
        "fetched": 0,
    }

    for feed in selected_feeds:
        try:
            records = fetch_feed_records(feed, limit=per_feed_limit)
            counts = upsert_indicators(records, db_path=db_path)
            message = f"Fetched {len(records)} indicators from {feed.name}."
            update_refresh_state(
                feed_name=feed.name,
                status="success",
                message=message,
                total_fetched=len(records),
                inserted_count=counts["inserted"],
                updated_count=counts["updated"],
                db_path=db_path,
            )
            summary["feeds"].append(
                {
                    "feed": feed.name,
                    "status": "success",
                    "message": message,
                    "fetched": len(records),
                    "inserted": counts["inserted"],
                    "updated": counts["updated"],
                }
            )
            summary["fetched"] += len(records)
            summary["inserted"] += counts["inserted"]
            summary["updated"] += counts["updated"]
        except Exception as exc:
            update_refresh_state(
                feed_name=feed.name,
                status="error",
                message=str(exc),
                total_fetched=0,
                inserted_count=0,
                updated_count=0,
                db_path=db_path,
            )
            summary["feeds"].append(
                {
                    "feed": feed.name,
                    "status": "error",
                    "message": str(exc),
                    "fetched": 0,
                    "inserted": 0,
                    "updated": 0,
                }
            )

    return summary


def maybe_refresh_live_feeds(
    refresh_interval_minutes: int = 15,
    per_feed_limit: int = 100,
    db_path: Path | str = DB_PATH,
) -> dict[str, object]:
    initialize_database(db_path=db_path)
    status = get_refresh_status(db_path=db_path)
    latest_success = None

    for feed_status in status:
        success_value = feed_status.get("last_success_at")
        if success_value:
            parsed = datetime.fromisoformat(success_value)
            latest_success = parsed if latest_success is None else max(latest_success, parsed)

    if latest_success is None:
        return refresh_live_feeds(per_feed_limit=per_feed_limit, db_path=db_path)

    age = datetime.now(UTC) - latest_success.astimezone(UTC)
    if age >= timedelta(minutes=refresh_interval_minutes):
        return refresh_live_feeds(per_feed_limit=per_feed_limit, db_path=db_path)

    return {
        "refreshed_at": utc_now_iso(),
        "feeds": [],
        "inserted": 0,
        "updated": 0,
        "fetched": 0,
        "skipped": True,
    }


def get_refresh_status(db_path: Path | str = DB_PATH) -> list[dict]:
    initialize_database(db_path=db_path)
    active_feed_names = [feed.name for feed in LIVE_FEEDS]
    if not active_feed_names:
        return []

    placeholders = ", ".join("?" for _ in active_feed_names)
    with get_connection(db_path) as connection:
        rows = connection.execute(
            f"""
            SELECT
                feed_name,
                last_refresh_at,
                last_success_at,
                status,
                message,
                inserted_count,
                updated_count,
                total_fetched
            FROM refresh_state
            WHERE feed_name IN ({placeholders})
            ORDER BY feed_name
            """,
            tuple(active_feed_names),
        ).fetchall()
    return [dict(row) for row in rows]


def get_all_indicators(db_path: Path | str = DB_PATH) -> list[dict]:
    with get_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM threat_indicators
            ORDER BY datetime(last_seen) DESC, confidence DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def search_indicators(
    indicator_value: str,
    db_path: Path | str = DB_PATH,
) -> list[dict]:
    with get_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM threat_indicators
            WHERE indicator_value LIKE ?
            ORDER BY datetime(last_seen) DESC, confidence DESC
            """,
            (f"%{indicator_value.strip()}%",),
        ).fetchall()
    return [dict(row) for row in rows]


def get_indicators_dataframe(
    search_value: Optional[str] = None,
    db_path: Path | str = DB_PATH,
) -> pd.DataFrame:
    query = """
        SELECT *
        FROM threat_indicators
    """
    params: tuple = ()

    if search_value:
        query += " WHERE indicator_value LIKE ?"
        params = (f"%{search_value.strip()}%",)

    query += " ORDER BY datetime(last_seen) DESC, confidence DESC"

    with get_connection(db_path) as connection:
        return pd.read_sql_query(query, connection, params=params)


if __name__ == "__main__":
    initialize_database()
    summary = refresh_live_feeds(per_feed_limit=50)
    total = len(get_all_indicators())
    print(
        f"Database initialized at {DB_PATH} with {total} threat indicators. "
        f"Live refresh inserted {summary['inserted']} and updated {summary['updated']}."
    )
