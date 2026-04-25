import argparse
import csv
import ipaddress
import io
import json
import os
import re
from datetime import datetime

from pymongo import MongoClient, ReplaceOne


def _now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def _normalize_url(url: str) -> str:
    return (url or "").strip()


def _load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _iter_csv_content_lines(path: str):
    """
    abuse.ch feeds often start with '#' comment blocks. Some feeds also comment the header as '# col1,col2...'.
    This iterator strips those comment lines so csv.DictReader sees the real header + rows.
    """
    with open(path, "r", encoding="utf-8", newline="") as f:
        for line in f:
            if not line:
                continue
            stripped = line.lstrip()
            if stripped.startswith("#"):
                candidate = stripped[1:].lstrip()
                # Handle commented header lines like: "# id,dateadded,..."
                if candidate and ("," in candidate) and not candidate.startswith("#"):
                    yield candidate
                continue
            yield line


def _bulk_upsert(collection, key_field: str, docs: list[dict], extra_key_fields: list[str] | None = None):
    extra_key_fields = extra_key_fields or []
    ops = []
    for doc in docs:
        if key_field not in doc or doc[key_field] in (None, ""):
            continue
        selector = {key_field: doc[key_field]}
        for k in extra_key_fields:
            selector[k] = doc.get(k)
        ops.append(ReplaceOne(selector, doc, upsert=True))
    if not ops:
        return {"attempted": 0, "upserted": 0, "modified": 0, "matched": 0}

    result = collection.bulk_write(ops, ordered=False)
    return {
        "attempted": len(ops),
        "upserted": getattr(result, "upserted_count", 0),
        "modified": getattr(result, "modified_count", 0),
        "matched": getattr(result, "matched_count", 0),
    }


def _warn_missing(path: str, label: str):
    if path and os.path.exists(path):
        return False
    print(f"[WARN] Missing {label}: {path}")
    return True


def load_misp_warninglists(db, json_paths: list[str]):
    """
    Supports common warninglist structures:
    - { "values": [ ... ] }
    - { "list": [ ... ] }
    - [ ... ]
    - { ... } (single object)
    """
    col = db["misp_warnings"]
    docs = []

    for path in json_paths:
        if _warn_missing(path, "MISP JSON"):
            continue

        payload = _load_json(path)
        values = None
        meta = {"source": "misp_warninglist", "source_file": os.path.basename(path), "ingested_at": _now_iso()}

        if isinstance(payload, dict):
            if isinstance(payload.get("values"), list):
                values = payload["values"]
            elif isinstance(payload.get("list"), list):
                values = payload["list"]
            else:
                # Some warninglists are dicts with nested "Warninglist" / "WarninglistEntry"
                if isinstance(payload.get("WarninglistEntry"), list):
                    values = payload["WarninglistEntry"]
                elif isinstance(payload.get("Warninglist"), dict) and isinstance(payload["Warninglist"].get("values"), list):
                    values = payload["Warninglist"]["values"]

        if values is None:
            values = payload if isinstance(payload, list) else [payload]

        for item in values:
            if isinstance(item, str):
                docs.append({**meta, "value": item})
            elif isinstance(item, dict):
                value = item.get("value") or item.get("name") or item.get("indicator") or item.get("entry")
                if not value:
                    # If the dict is already an entry object, store it as-is with a computed value when possible.
                    continue
                docs.append({**meta, "value": str(value), "raw": item})
            else:
                continue

    return _bulk_upsert(col, "value", docs, extra_key_fields=["source_file"])


def load_urlhaus_csv(db, csv_path: str):
    col = db["malicious_urls"]
    if _warn_missing(csv_path, "URLhaus CSV"):
        return {"attempted": 0, "upserted": 0, "modified": 0, "matched": 0}

    docs = []
    reader = csv.DictReader(_iter_csv_content_lines(csv_path))
    for row in reader:
        url = _normalize_url(row.get("url") or "")
        if not url:
            continue
        tags_raw = (row.get("tags") or "").strip()
        tags = [t.strip() for t in re.split(r"[|,]", tags_raw) if t.strip()] if tags_raw else []
        docs.append(
            {
                "source": "urlhaus",
                "ingested_at": _now_iso(),
                "id": row.get("id"),
                "dateadded": row.get("dateadded"),
                "url": url,
                "url_status": row.get("url_status"),
                "threat": row.get("threat"),
                "tags": tags,
                "urlhaus_link": row.get("urlhaus_link"),
                "reporter": row.get("reporter"),
                "raw": row,
            }
        )

    return _bulk_upsert(col, "url", docs)


def _guess_feodo_columns(fieldnames: list[str]):
    lower = [c.lower().strip() for c in fieldnames]

    def pick(candidates):
        for cand in candidates:
            if cand in lower:
                return fieldnames[lower.index(cand)]
        return None

    ip_col = pick(["ip", "dst_ip", "host", "c2", "c2_ip", "c2ip", "ip_address"])
    fam_col = pick(["malware", "family", "malware_family", "malwarefamily", "malware family", "botnet", "name"])
    return ip_col, fam_col


def load_feodo_csv(db, csv_path: str):
    col = db["malicious_ips"]
    if _warn_missing(csv_path, "Feodo CSV"):
        return {"attempted": 0, "upserted": 0, "modified": 0, "matched": 0}

    docs = []
    reader = csv.DictReader(_iter_csv_content_lines(csv_path))
    ip_col, fam_col = _guess_feodo_columns(reader.fieldnames or [])
    for row in reader:
        ip = (row.get(ip_col) if ip_col else None) or ""
        ip = ip.strip()
        if not ip or not _is_ip(ip):
            continue
        family = (row.get(fam_col) if fam_col else None) or row.get("malware") or row.get("family") or ""
        docs.append(
            {
                "source": "feodo_tracker",
                "ingested_at": _now_iso(),
                "ip": ip,
                "dst_port": row.get("dst_port"),
                "c2_status": row.get("c2_status"),
                "first_seen_utc": row.get("first_seen_utc"),
                "last_online": row.get("last_online"),
                "malware_family": (family or "").strip() or None,
                "raw": row,
            }
        )

    return _bulk_upsert(col, "ip", docs)


def check_indicator(value: str, mongo_uri: str = "mongodb://localhost:27017"):
    """
    Searches across:
    - drift_db.misp_warnings (by exact value)
    - drift_db.malicious_urls (by exact url)
    - drift_db.malicious_ips (by exact ip)
    Returns a list of matches with threat context.
    """
    client = MongoClient(mongo_uri)
    db = client["drift_db"]

    value = (value or "").strip()
    if not value:
        return []

    matches = []

    if _is_ip(value):
        for doc in db["malicious_ips"].find({"ip": value}, {"_id": 0, "ip": 1, "malware_family": 1, "source": 1}):
            matches.append({"collection": "malicious_ips", "match": doc.get("ip"), "context": doc})
    else:
        url = _normalize_url(value)
        for doc in db["malicious_urls"].find({"url": url}, {"_id": 0, "url": 1, "threat": 1, "tags": 1, "url_status": 1, "source": 1}):
            matches.append({"collection": "malicious_urls", "match": doc.get("url"), "context": doc})

    for doc in db["misp_warnings"].find({"value": value}, {"_id": 0, "value": 1, "source_file": 1, "source": 1}):
        matches.append({"collection": "misp_warnings", "match": doc.get("value"), "context": doc})

    return matches


def main():
    parser = argparse.ArgumentParser(description="Load Drift datasets into MongoDB (drift_db).")
    parser.add_argument("--mongo", default="mongodb://localhost:27017", help="MongoDB connection URI")

    parser.add_argument("--misp1", default=r"c:\Users\MSI\Downloads\list.json", help="MISP warninglists JSON file #1")
    parser.add_argument("--misp2", default=r"c:\Users\MSI\Downloads\list (1).json", help="MISP warninglists JSON file #2")
    parser.add_argument("--urlhaus", default=r"c:\Users\MSI\Downloads\urlhaus.csv", help="URLhaus CSV file")
    parser.add_argument("--feodo", default=r"c:\Users\MSI\Downloads\feodo.csv", help="Feodo Tracker CSV file")

    parser.add_argument("--check", default="", help="Optional: check a URL or IP after loading")
    args = parser.parse_args()

    client = MongoClient(args.mongo)
    db = client["drift_db"]

    misp_res = load_misp_warninglists(db, [args.misp1, args.misp2])
    urlhaus_res = load_urlhaus_csv(db, args.urlhaus)
    feodo_res = load_feodo_csv(db, args.feodo)

    print("Done loading into drift_db:")
    print("- misp_warnings")
    print("- malicious_urls")
    print("- malicious_ips")
    print("\nImport summary (attempted / upserted / modified / matched):")
    print(f"- misp_warnings: {misp_res['attempted']} / {misp_res['upserted']} / {misp_res['modified']} / {misp_res['matched']}")
    print(
        f"- malicious_urls: {urlhaus_res['attempted']} / {urlhaus_res['upserted']} / {urlhaus_res['modified']} / {urlhaus_res['matched']}"
    )
    print(f"- malicious_ips: {feodo_res['attempted']} / {feodo_res['upserted']} / {feodo_res['modified']} / {feodo_res['matched']}")

    if args.check:
        hits = check_indicator(args.check, mongo_uri=args.mongo)
        print("\ncheck_indicator results:")
        print(json.dumps(hits, indent=2))


if __name__ == "__main__":
    main()

