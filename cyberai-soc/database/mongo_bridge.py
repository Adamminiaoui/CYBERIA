from __future__ import annotations

import ipaddress
import os
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import pandas as pd

try:
    from pymongo import MongoClient
except Exception:  # pragma: no cover - handled at runtime in the dashboard
    MongoClient = None


DEFAULT_MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DEFAULT_MONGO_DB = os.getenv("MONGO_DB", "drift_db")
GLOBAL_COLLECTIONS = {"malicious_urls", "malicious_ips", "misp_warnings"}
DEFAULT_WORKPLACE_COLLECTION = os.getenv("WORKPLACE_COLLECTION", "workplace_logs")

GLOBAL_COLUMNS = [
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
WORKPLACE_COLUMNS = [
    "event_collection",
    "event_id",
    "event_time",
    "user",
    "asset",
    "source_ip",
    "destination_ip",
    "observable_type",
    "observable_value",
    "field_path",
    "raw_summary",
]

URL_RE = re.compile(r"https?://[^\s\"'<>),]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

TIME_KEYS = {
    "@timestamp",
    "timestamp",
    "time",
    "datetime",
    "event_time",
    "created_at",
    "ingested_at",
    "date",
    "dateadded",
    "first_seen",
    "last_seen",
}
USER_KEYS = {"user", "username", "account", "account_name", "email", "principal", "src_user"}
ASSET_KEYS = {"host", "hostname", "computer", "machine", "device", "asset", "endpoint"}
SRC_IP_KEYS = {"src_ip", "source_ip", "client_ip", "local_ip"}
DST_IP_KEYS = {"dst_ip", "dest_ip", "destination_ip", "remote_ip", "server_ip"}


def _empty_global_frame() -> pd.DataFrame:
    return pd.DataFrame(columns=GLOBAL_COLUMNS)


def _empty_workplace_frame() -> pd.DataFrame:
    return pd.DataFrame(columns=WORKPLACE_COLUMNS)


def _connect(mongo_uri: str = DEFAULT_MONGO_URI):
    if MongoClient is None:
        raise RuntimeError("pymongo is not installed. Install requirements.txt before running Mongo pages.")
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=1800)
    client.admin.command("ping")
    return client


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        return ""
    return str(value).strip()


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _parse_time(value: Any) -> str:
    raw = _safe_str(value)
    if not raw:
        return _now_iso()
    cleaned = raw.replace("Z", "+00:00").replace(" UTC", "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y"):
        try:
            return datetime.strptime(cleaned, fmt).replace(tzinfo=UTC).isoformat()
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(cleaned).astimezone(UTC).replace(microsecond=0).isoformat()
    except ValueError:
        return _now_iso()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _domain_from_url(value: str) -> str:
    parsed = urlparse(value if value.lower().startswith(("http://", "https://")) else f"http://{value}")
    return parsed.hostname.lower() if parsed.hostname else ""


def _normalize_domain(value: str) -> str:
    cleaned = value.strip().lower().strip(".")
    cleaned = cleaned.removeprefix("*.").removeprefix("www.")
    return cleaned


def _classify_observable(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        return ""
    if cleaned.lower().startswith(("http://", "https://")):
        return "url"
    if _is_ip(cleaned):
        return "ip"
    if HASH_RE.fullmatch(cleaned):
        return "hash"
    if DOMAIN_RE.fullmatch(cleaned.strip("*.")):
        return "domain"
    return "value"


def _infer_urlhaus_severity(doc: dict[str, Any]) -> tuple[int, str]:
    threat = _safe_str(doc.get("threat")).lower()
    status = _safe_str(doc.get("url_status")).lower()
    if status == "online":
        return 92, "critical" if "ransom" in threat else "high"
    if "malware" in threat or "phish" in threat:
        return 82, "high"
    return 68, "medium"


def _tag_string(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(_safe_str(item) for item in value if _safe_str(item))
    return _safe_str(value)


def _global_record(
    indicator_type: str,
    indicator_value: str,
    source: str,
    threat_type: str,
    confidence: int,
    severity: str,
    first_seen: Any,
    last_seen: Any,
    collection: str,
    tags: Any = "",
) -> dict[str, Any]:
    return {
        "indicator_type": indicator_type,
        "indicator_value": indicator_value,
        "source": source,
        "threat_type": threat_type,
        "confidence": max(0, min(100, int(confidence))),
        "severity": severity,
        "first_seen": _parse_time(first_seen),
        "last_seen": _parse_time(last_seen or first_seen),
        "collection": collection,
        "tags": _tag_string(tags),
    }


def get_mongo_status(
    mongo_uri: str = DEFAULT_MONGO_URI,
    database_name: str = DEFAULT_MONGO_DB,
) -> dict[str, Any]:
    status: dict[str, Any] = {
        "ok": False,
        "mongo_uri": mongo_uri,
        "database": database_name,
        "collections": [],
        "error": "",
    }
    try:
        client = _connect(mongo_uri)
        try:
            db = client[database_name]
            collection_names = db.list_collection_names()
            for name in collection_names:
                if name.startswith("system."):
                    continue
                status["collections"].append(
                    {
                        "collection": name,
                        "documents": db[name].estimated_document_count(),
                        "role": "global_intel" if name in GLOBAL_COLLECTIONS else "workplace_logs",
                    }
                )
            status["ok"] = True
        finally:
            client.close()
    except Exception as exc:
        status["error"] = str(exc)
    return status


def load_mongo_global_indicators(
    mongo_uri: str = DEFAULT_MONGO_URI,
    database_name: str = DEFAULT_MONGO_DB,
    per_collection_limit: int = 50000,
) -> pd.DataFrame:
    records: list[dict[str, Any]] = []
    try:
        client = _connect(mongo_uri)
        try:
            db = client[database_name]
            for doc in db["malicious_urls"].find({}, {"_id": 0}).limit(per_collection_limit):
                url_value = _safe_str(doc.get("url"))
                if not url_value:
                    continue
                confidence, severity = _infer_urlhaus_severity(doc)
                threat_type = _safe_str(doc.get("threat")) or "malware_url"
                first_seen = doc.get("dateadded") or doc.get("ingested_at")
                last_seen = doc.get("last_online") or doc.get("ingested_at") or first_seen
                records.append(
                    _global_record(
                        "url",
                        url_value,
                        _safe_str(doc.get("source")) or "urlhaus",
                        threat_type,
                        confidence,
                        severity,
                        first_seen,
                        last_seen,
                        "malicious_urls",
                        doc.get("tags"),
                    )
                )
                domain = _domain_from_url(url_value)
                if domain:
                    records.append(
                        _global_record(
                            "domain",
                            domain,
                            "urlhaus derived",
                            threat_type,
                            max(confidence - 8, 0),
                            severity,
                            first_seen,
                            last_seen,
                            "malicious_urls",
                            doc.get("tags"),
                        )
                    )

            for doc in db["malicious_ips"].find({}, {"_id": 0}).limit(per_collection_limit):
                ip_value = _safe_str(doc.get("ip") or doc.get("dst_ip"))
                if not ip_value:
                    continue
                status = _safe_str(doc.get("c2_status")).lower()
                confidence = 90 if status == "online" else 72
                severity = "critical" if status == "online" else "high"
                family = _safe_str(doc.get("malware_family")) or "malware_c2"
                records.append(
                    _global_record(
                        "ip",
                        ip_value,
                        _safe_str(doc.get("source")) or "feodo_tracker",
                        family,
                        confidence,
                        severity,
                        doc.get("first_seen_utc") or doc.get("ingested_at"),
                        doc.get("last_online") or doc.get("ingested_at"),
                        "malicious_ips",
                        family,
                    )
                )

            for doc in db["misp_warnings"].find({}, {"_id": 0}).limit(per_collection_limit):
                value = _safe_str(doc.get("value"))
                indicator_type = _classify_observable(value)
                if not value or indicator_type == "value":
                    continue
                normalized_value = _normalize_domain(value) if indicator_type == "domain" else value
                records.append(
                    _global_record(
                        indicator_type,
                        normalized_value,
                        "MISP warninglist",
                        "warninglist_context",
                        35,
                        "low",
                        doc.get("ingested_at"),
                        doc.get("ingested_at"),
                        "misp_warnings",
                        doc.get("source_file"),
                    )
                )
        finally:
            client.close()
    except Exception:
        return _empty_global_frame()

    if not records:
        return _empty_global_frame()

    frame = pd.DataFrame(records, columns=GLOBAL_COLUMNS)
    frame = frame.drop_duplicates(subset=["indicator_type", "indicator_value", "source"])
    return frame.reset_index(drop=True)


def _walk_scalars(value: Any, prefix: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            yield from _walk_scalars(child, next_prefix)
    elif isinstance(value, list):
        for index, child in enumerate(value[:20]):
            yield from _walk_scalars(child, f"{prefix}[{index}]")
    else:
        yield prefix, value


def _first_value(doc: dict[str, Any], key_candidates: set[str]) -> str:
    for path, value in _walk_scalars(doc):
        key = path.split(".")[-1].split("[")[0].lower()
        if key in key_candidates:
            text = _safe_str(value)
            if text:
                return text
    return ""


def _event_metadata(doc: dict[str, Any]) -> dict[str, str]:
    return {
        "event_time": _parse_time(_first_value(doc, TIME_KEYS)),
        "user": _first_value(doc, USER_KEYS),
        "asset": _first_value(doc, ASSET_KEYS),
        "source_ip": _first_value(doc, SRC_IP_KEYS),
        "destination_ip": _first_value(doc, DST_IP_KEYS),
    }


def _add_observable(rows: list[dict[str, str]], seen: set[tuple[str, str]], obs_type: str, value: str, field_path: str) -> None:
    if not value:
        return
    normalized = _normalize_domain(value) if obs_type == "domain" else value.strip()
    key = (obs_type, normalized.lower())
    if key in seen:
        return
    seen.add(key)
    rows.append({"observable_type": obs_type, "observable_value": normalized, "field_path": field_path})


def _extract_observables(doc: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for path, value in _walk_scalars(doc):
        text = _safe_str(value)
        if not text:
            continue
        key_hint = path.split(".")[-1].lower()

        for match in URL_RE.findall(text):
            _add_observable(rows, seen, "url", match, path)
            domain = _domain_from_url(match)
            if domain:
                _add_observable(rows, seen, "domain", domain, path)

        for match in IP_RE.findall(text):
            if _is_ip(match):
                _add_observable(rows, seen, "ip", match, path)

        for match in HASH_RE.findall(text):
            _add_observable(rows, seen, "hash", match.lower(), path)

        if any(token in key_hint for token in ["domain", "host", "fqdn", "dns", "query"]):
            for match in DOMAIN_RE.findall(text):
                _add_observable(rows, seen, "domain", match, path)

    return rows


def _raw_summary(doc: dict[str, Any]) -> str:
    parts = []
    for key in ("event_type", "action", "method", "status", "process", "url", "domain", "ip", "message"):
        value = _safe_str(doc.get(key))
        if value:
            parts.append(f"{key}={value[:80]}")
    return " | ".join(parts)[:240]


def load_workspace_observables(
    mongo_uri: str = DEFAULT_MONGO_URI,
    database_name: str = DEFAULT_MONGO_DB,
    per_collection_limit: int = 5000,
) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    try:
        client = _connect(mongo_uri)
        try:
            db = client[database_name]
            collection_names = [
                name
                for name in db.list_collection_names()
                if name not in GLOBAL_COLLECTIONS and not name.startswith("system.")
            ]

            for collection_name in collection_names:
                cursor = db[collection_name].find({}).limit(per_collection_limit)
                for doc in cursor:
                    metadata = _event_metadata(doc)
                    event_id = _safe_str(doc.get("_id"))
                    for observable in _extract_observables(doc):
                        rows.append(
                            {
                                "event_collection": collection_name,
                                "event_id": event_id,
                                **metadata,
                                **observable,
                                "raw_summary": _raw_summary(doc),
                            }
                        )
        finally:
            client.close()
    except Exception:
        return _empty_workplace_frame()

    if not rows:
        return _empty_workplace_frame()

    frame = pd.DataFrame(rows, columns=WORKPLACE_COLUMNS)
    frame["event_time"] = pd.to_datetime(frame["event_time"], format="mixed", utc=True, errors="coerce")
    frame = frame.drop_duplicates(
        subset=["event_collection", "event_id", "observable_type", "observable_value", "field_path"]
    )
    return frame.reset_index(drop=True)


def ensure_workplace_logs(
    global_indicators: pd.DataFrame,
    mongo_uri: str = DEFAULT_MONGO_URI,
    database_name: str = DEFAULT_MONGO_DB,
    workplace_collection: str = DEFAULT_WORKPLACE_COLLECTION,
    seed_events: int = 40,
) -> dict[str, Any]:
    """
    If no workplace log collection exists, seed a lightweight demo stream INTO MongoDB
    (not in-memory) so correlation + AI pages always operate on the actual drift_db.

    This is a PoC safety net: real SOC deployments should point this to real workplace logs.
    """
    result: dict[str, Any] = {"seeded": False, "collection": workplace_collection, "inserted_events": 0}
    if global_indicators.empty:
        return result

    try:
        client = _connect(mongo_uri)
        try:
            db = client[database_name]
            existing = db.list_collection_names()
            # If ANY non-global collection has docs, assume workplace logs exist already.
            for name in existing:
                if name in GLOBAL_COLLECTIONS or name.startswith("system."):
                    continue
                if db[name].estimated_document_count() > 0:
                    return {**result, "seeded": False, "collection": name, "inserted_events": 0}

            col = db[workplace_collection]
            if col.estimated_document_count() > 0:
                return {**result, "seeded": False, "collection": workplace_collection, "inserted_events": 0}

            candidates = global_indicators[
                (global_indicators["indicator_type"].isin(["url", "domain", "ip", "hash"]))
                & (global_indicators["threat_type"].astype(str) != "warninglist_context")
            ].head(seed_events)
            if candidates.empty:
                candidates = global_indicators[global_indicators["indicator_type"].isin(["url", "domain", "ip", "hash"])].head(
                    seed_events
                )

            now = datetime.now(UTC)
            users = ["finance.user@corp.local", "ops.engineer@corp.local", "helpdesk@corp.local", "analyst@corp.local"]
            assets = ["FIN-LAP-014", "OPS-WS-022", "HELPDESK-07", "SOC-SANDBOX-01"]

            docs: list[dict[str, Any]] = []
            for index, (_, indicator) in enumerate(candidates.iterrows()):
                value = _safe_str(indicator.get("indicator_value"))
                obs_type = _safe_str(indicator.get("indicator_type"))
                docs.append(
                    {
                        "event_time": (now).replace(microsecond=0).isoformat(),
                        "user": users[index % len(users)],
                        "host": assets[index % len(assets)],
                        # Keep fields simple so the extractor finds them reliably.
                        "observable_type": obs_type,
                        "observable_value": value,
                        "message": f"Demo workplace event referencing {obs_type}={value}",
                        "source": "demo_seed",
                    }
                )
                now = now.replace(microsecond=0)  # stable formatting
                now = now  # explicit

            if docs:
                col.insert_many(docs, ordered=False)
                result["seeded"] = True
                result["inserted_events"] = len(docs)
        finally:
            client.close()
    except Exception:
        return result

    return result


def load_mongo_context(
    mongo_uri: str = DEFAULT_MONGO_URI,
    database_name: str = DEFAULT_MONGO_DB,
) -> dict[str, Any]:
    global_indicators = load_mongo_global_indicators(mongo_uri=mongo_uri, database_name=database_name)
    workspace = load_workspace_observables(mongo_uri=mongo_uri, database_name=database_name)
    seed_info = {"seeded": False, "collection": DEFAULT_WORKPLACE_COLLECTION, "inserted_events": 0}
    if workspace.empty and not global_indicators.empty:
        seed_info = ensure_workplace_logs(
            global_indicators=global_indicators,
            mongo_uri=mongo_uri,
            database_name=database_name,
        )
        # Reload after seeding.
        workspace = load_workspace_observables(mongo_uri=mongo_uri, database_name=database_name)

    return {
        "status": get_mongo_status(mongo_uri=mongo_uri, database_name=database_name),
        "global_indicators": global_indicators,
        "workspace_observables": workspace,
        "workplace_seed": seed_info,
    }
