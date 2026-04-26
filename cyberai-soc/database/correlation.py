from __future__ import annotations

from urllib.parse import urlparse

import pandas as pd


CORRELATION_COLUMNS = [
    "event_time",
    "event_collection",
    "event_id",
    "user",
    "asset",
    "source_ip",
    "destination_ip",
    "observable_type",
    "observable_value",
    "matched_indicator",
    "matched_type",
    "source",
    "threat_type",
    "severity",
    "confidence",
    "collection",
    "tags",
    "match_quality",
]


def empty_correlation_frame() -> pd.DataFrame:
    return pd.DataFrame(columns=CORRELATION_COLUMNS)


def _safe_str(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _domain_from_url(value: str) -> str:
    parsed = urlparse(value if value.lower().startswith(("http://", "https://")) else f"http://{value}")
    return parsed.hostname.lower() if parsed.hostname else ""


def _canonical(obs_type: str, value: str) -> str:
    cleaned = _safe_str(value).lower().strip()
    if obs_type == "url":
        parsed = urlparse(cleaned)
        if parsed.scheme and parsed.netloc:
            path = parsed.path.rstrip("/")
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        return cleaned.rstrip("/")
    if obs_type == "domain":
        return cleaned.strip(".").removeprefix("*.").removeprefix("www.")
    if obs_type == "hash":
        return cleaned.removeprefix("sha256:")
    return cleaned


def _indicator_aliases(row: pd.Series) -> set[tuple[str, str, str]]:
    obs_type = _safe_str(row.get("indicator_type")).lower()
    value = _safe_str(row.get("indicator_value"))
    aliases = {(obs_type, _canonical(obs_type, value), "exact")}

    if obs_type == "url":
        domain = _domain_from_url(value)
        if domain:
            aliases.add(("domain", _canonical("domain", domain), "url_domain"))
    elif obs_type == "domain":
        aliases.add(("domain", _canonical("domain", value), "exact"))

    return {alias for alias in aliases if alias[1]}


def correlate_observables(
    global_indicators: pd.DataFrame,
    workspace_observables: pd.DataFrame,
) -> pd.DataFrame:
    if global_indicators.empty or workspace_observables.empty:
        return empty_correlation_frame()

    index: dict[tuple[str, str], list[tuple[pd.Series, str]]] = {}
    for _, row in global_indicators.iterrows():
        for alias_type, alias_value, match_quality in _indicator_aliases(row):
            index.setdefault((alias_type, alias_value), []).append((row, match_quality))

    rows: list[dict] = []
    for _, event in workspace_observables.iterrows():
        event_type = _safe_str(event.get("observable_type")).lower()
        event_value = _safe_str(event.get("observable_value"))
        lookup_keys = {(event_type, _canonical(event_type, event_value))}

        if event_type == "url":
            domain = _domain_from_url(event_value)
            if domain:
                lookup_keys.add(("domain", _canonical("domain", domain)))

        for lookup_key in lookup_keys:
            for indicator, match_quality in index.get(lookup_key, []):
                rows.append(
                    {
                        "event_time": event.get("event_time"),
                        "event_collection": event.get("event_collection"),
                        "event_id": event.get("event_id"),
                        "user": event.get("user"),
                        "asset": event.get("asset"),
                        "source_ip": event.get("source_ip"),
                        "destination_ip": event.get("destination_ip"),
                        "observable_type": event_type,
                        "observable_value": event_value,
                        "matched_indicator": indicator.get("indicator_value"),
                        "matched_type": indicator.get("indicator_type"),
                        "source": indicator.get("source"),
                        "threat_type": indicator.get("threat_type"),
                        "severity": indicator.get("severity"),
                        "confidence": indicator.get("confidence"),
                        "collection": indicator.get("collection"),
                        "tags": indicator.get("tags"),
                        "match_quality": match_quality,
                    }
                )

    if not rows:
        return empty_correlation_frame()

    frame = pd.DataFrame(rows, columns=CORRELATION_COLUMNS)
    frame["event_time"] = pd.to_datetime(frame["event_time"], format="mixed", utc=True, errors="coerce")
    frame["confidence"] = pd.to_numeric(frame["confidence"], errors="coerce").fillna(0).astype(int)
    return frame.drop_duplicates().reset_index(drop=True)
