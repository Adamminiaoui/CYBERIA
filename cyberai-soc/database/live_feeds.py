from __future__ import annotations

import gzip
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse
from urllib.request import Request, urlopen


DEFAULT_USER_AGENT = "cyberai-soc-threat-intel/1.0"


@dataclass(frozen=True)
class FeedDefinition:
    name: str
    url: str
    indicator_type: str
    threat_type: str
    source: str
    confidence: int
    severity: str
    format_type: str
    derive_domain: bool = False
    headers: dict[str, str] | None = None
    post_data: bytes | None = None


LIVE_FEEDS = [
    FeedDefinition(
        name="openphish-community",
        url="https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
        indicator_type="url",
        threat_type="phishing",
        source="OpenPhish",
        confidence=90,
        severity="high",
        format_type="plain_text",
        derive_domain=True,
    ),
]


PHISHTANK_APP_KEY = os.getenv("PHISHTANK_APP_KEY")
if PHISHTANK_APP_KEY:
    LIVE_FEEDS.append(
        FeedDefinition(
            name="phishtank-online-valid",
            url=f"http://data.phishtank.com/data/{PHISHTANK_APP_KEY}/online-valid.json",
            indicator_type="url",
            threat_type="phishing",
            source="PhishTank",
            confidence=88,
            severity="high",
            format_type="phishtank_json",
            derive_domain=True,
            headers={"User-Agent": os.getenv("PHISHTANK_USER_AGENT", DEFAULT_USER_AGENT)},
        )
    )

ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY")
if ABUSECH_AUTH_KEY:
    LIVE_FEEDS.append(
        FeedDefinition(
            name="threatfox-recent-iocs",
            url="https://threatfox-api.abuse.ch/api/v1/",
            indicator_type="domain",
            threat_type="c2",
            source="ThreatFox",
            confidence=85,
            severity="high",
            format_type="threatfox_json",
            headers={"Auth-Key": ABUSECH_AUTH_KEY},
            post_data=b'{"query":"get_iocs","days":1}',
        )
    )
    LIVE_FEEDS.append(
        FeedDefinition(
            name="malwarebazaar-recent-detections",
            url="https://mb-api.abuse.ch/api/v1/",
            indicator_type="domain",
            threat_type="malware",
            source="MalwareBazaar",
            confidence=80,
            severity="high",
            format_type="malwarebazaar_json",
            headers={"Auth-Key": ABUSECH_AUTH_KEY},
            post_data=b"query=recent_detections&hours=6",
        )
    )


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def build_request(
    url: str,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
) -> Request:
    request_headers = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        request_headers.update(headers)
    return Request(url, headers=request_headers, data=data)


def read_response_text(
    url: str,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
) -> str:
    with urlopen(build_request(url, headers=headers, data=data), timeout=30) as response:
        payload = response.read()
        if url.endswith(".gz"):
            payload = gzip.decompress(payload)
        return payload.decode("utf-8", errors="replace")


def normalize_url_record(
    url_value: str,
    source: str,
    threat_type: str,
    confidence: int,
    severity: str,
    created_at: str | None = None,
    first_seen: str | None = None,
    last_seen: str | None = None,
    derive_domain: bool = False,
) -> list[dict]:
    now = utc_now_iso()
    created_at = created_at or now
    first_seen = first_seen or created_at
    last_seen = last_seen or created_at

    records = [
        {
            "indicator_type": "url",
            "indicator_value": url_value.strip(),
            "threat_type": threat_type,
            "source": source,
            "confidence": confidence,
            "severity": severity,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "created_at": created_at,
        }
    ]

    if derive_domain:
        domain_value = urlparse(url_value.strip()).netloc.lower()
        if domain_value:
            records.append(
                {
                    "indicator_type": "domain",
                    "indicator_value": domain_value,
                    "threat_type": threat_type,
                    "source": f"{source} (derived)",
                    "confidence": max(confidence - 5, 0),
                    "severity": severity,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "created_at": created_at,
                }
            )

    return records


def normalize_indicator_type(ioc_type: str) -> str | None:
    normalized = ioc_type.strip().lower()
    if normalized == "url":
        return "url"
    if normalized == "domain":
        return "domain"
    if normalized in {"ip", "ip:port"}:
        return "ip"
    return None


def normalize_timestamp_without_timezone(raw_value: str | None) -> str:
    if not raw_value:
        return utc_now_iso()

    cleaned = raw_value.replace(" UTC", "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(cleaned, fmt).replace(tzinfo=UTC).isoformat()
        except ValueError:
            continue
    return utc_now_iso()


def fetch_plain_text_feed(feed: FeedDefinition, limit: int) -> list[dict]:
    text = read_response_text(feed.url, headers=feed.headers, data=feed.post_data)
    indicators: list[dict] = []

    for line in text.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        indicators.extend(
            normalize_url_record(
                url_value=candidate,
                source=feed.source,
                threat_type=feed.threat_type,
                confidence=feed.confidence,
                severity=feed.severity,
                derive_domain=feed.derive_domain,
            )
        )
        if len(indicators) >= limit * (2 if feed.derive_domain else 1):
            break

    return indicators


def fetch_phishtank_json(feed: FeedDefinition, limit: int) -> list[dict]:
    text = read_response_text(feed.url, headers=feed.headers, data=feed.post_data)
    payload = json.loads(text)
    indicators: list[dict] = []

    for item in payload[:limit]:
        url_value = str(item.get("url", "")).strip()
        if not url_value:
            continue

        verification_time = item.get("verification_time") or item.get("submission_time")
        normalized_time = normalize_feed_datetime(verification_time)
        severity = "critical" if item.get("target") else feed.severity

        indicators.extend(
            normalize_url_record(
                url_value=url_value,
                source=feed.source,
                threat_type=feed.threat_type,
                confidence=feed.confidence,
                severity=severity,
                created_at=normalized_time,
                first_seen=normalize_feed_datetime(item.get("submission_time")),
                last_seen=normalized_time,
                derive_domain=feed.derive_domain,
            )
        )

    return indicators


def fetch_threatfox_json(feed: FeedDefinition, limit: int) -> list[dict]:
    text = read_response_text(feed.url, headers=feed.headers, data=feed.post_data)
    payload = json.loads(text)
    indicators: list[dict] = []

    for item in payload.get("data", [])[:limit]:
        indicator_type = normalize_indicator_type(str(item.get("ioc_type", "")))
        indicator_value = str(item.get("ioc", "")).strip()
        if not indicator_type or not indicator_value:
            continue

        first_seen = normalize_timestamp_without_timezone(item.get("first_seen"))
        last_seen = normalize_timestamp_without_timezone(item.get("last_seen")) if item.get("last_seen") else first_seen
        severity = "critical" if str(item.get("threat_type", "")).lower() == "botnet_cc" else feed.severity

        indicators.append(
            {
                "indicator_type": indicator_type,
                "indicator_value": indicator_value,
                "threat_type": str(item.get("threat_type", feed.threat_type)).lower(),
                "source": feed.source,
                "confidence": int(item.get("confidence_level") or feed.confidence),
                "severity": severity,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "created_at": first_seen,
            }
        )

    return indicators


def fetch_malwarebazaar_json(feed: FeedDefinition, limit: int) -> list[dict]:
    text = read_response_text(feed.url, headers=feed.headers, data=feed.post_data)
    payload = json.loads(text)
    indicators: list[dict] = []

    for item in payload.get("data", [])[:limit]:
        sha256_hash = str(item.get("sha256_hash", "")).strip()
        if not sha256_hash:
            continue

        first_seen = normalize_timestamp_without_timezone(item.get("first_seen"))
        last_seen = normalize_timestamp_without_timezone(item.get("last_seen")) if item.get("last_seen") else first_seen
        signature = str(item.get("signature") or "malware_sample").strip().lower().replace(" ", "_")
        severity = "critical" if str(item.get("file_type", "")).lower() in {"exe", "dll", "elf"} else feed.severity

        indicators.append(
            {
                "indicator_type": "hash",
                "indicator_value": f"sha256:{sha256_hash}",
                "threat_type": signature,
                "source": feed.source,
                "confidence": feed.confidence,
                "severity": severity,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "created_at": first_seen,
            }
        )

    return indicators


def normalize_feed_datetime(raw_value: str | None) -> str:
    if not raw_value:
        return utc_now_iso()

    try:
        return datetime.fromisoformat(raw_value.replace("Z", "+00:00")).astimezone(UTC).replace(
            microsecond=0
        ).isoformat()
    except ValueError:
        return utc_now_iso()


def fetch_feed_records(feed: FeedDefinition, limit: int = 100) -> list[dict]:
    if feed.format_type == "plain_text":
        return fetch_plain_text_feed(feed, limit=limit)
    if feed.format_type == "phishtank_json":
        return fetch_phishtank_json(feed, limit=limit)
    if feed.format_type == "threatfox_json":
        return fetch_threatfox_json(feed, limit=limit)
    if feed.format_type == "malwarebazaar_json":
        return fetch_malwarebazaar_json(feed, limit=limit)
    raise ValueError(f"Unsupported feed format: {feed.format_type}")
