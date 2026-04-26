from __future__ import annotations

import html
import json
import os
import re
import hashlib
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components
from streamlit_autorefresh import st_autorefresh


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from database.db import (
    get_indicators_dataframe,
    get_refresh_status,
    initialize_database,
    maybe_refresh_live_feeds,
    refresh_live_feeds,
)
from database.correlation import correlate_observables
from database.modeling import (
    build_soc_narrative,
    detect_workplace_anomalies,
    forecast_threat_trends,
    score_correlations,
)
from database.mongo_bridge import DEFAULT_MONGO_DB, DEFAULT_MONGO_URI, load_mongo_context


st.set_page_config(
    page_title="CyberAI Global Threat Intelligence Dashboard",
    layout="wide",
    initial_sidebar_state="collapsed",
)


SEVERITY_SCORE = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CYBER_COLORS = {
    "bg": "#07111a",
    "panel": "#0d1723",
    "panel_alt": "#111f2f",
    "grid": "#203246",
    "text": "#e8f1fb",
    "muted": "#8ca3b8",
    "accent": "#17c0eb",
    "accent_2": "#14f195",
    "warn": "#ffb020",
    "high": "#ff5a5f",
    "critical": "#ff2d55",
}
COUNTRY_COORDS = {
    "United States": (37.0902, -95.7129),
    "Russia": (61.524, 105.3188),
    "Germany": (51.1657, 10.4515),
    "Netherlands": (52.1326, 5.2913),
    "France": (46.2276, 2.2137),
    "United Kingdom": (55.3781, -3.436),
    "China": (35.8617, 104.1954),
    "Brazil": (-14.235, -51.9253),
    "Singapore": (1.3521, 103.8198),
    "India": (20.5937, 78.9629),
    "Canada": (56.1304, -106.3468),
    "Australia": (-25.2744, 133.7751),
    "Ukraine": (48.3794, 31.1656),
    "Romania": (45.9432, 24.9668),
    "Poland": (51.9194, 19.1451),
    "Global": (20.0, 0.0),
}
TLD_COUNTRY_MAP = {
    "ru": "Russia",
    "cn": "China",
    "de": "Germany",
    "nl": "Netherlands",
    "fr": "France",
    "uk": "United Kingdom",
    "co.uk": "United Kingdom",
    "us": "United States",
    "ca": "Canada",
    "au": "Australia",
    "in": "India",
    "br": "Brazil",
    "sg": "Singapore",
    "ua": "Ukraine",
    "ro": "Romania",
    "pl": "Poland",
}

def load_data() -> pd.DataFrame:
    initialize_database()
    frame = get_indicators_dataframe()

    if frame.empty:
        return frame

    for column in ["first_seen", "last_seen", "created_at"]:
        frame[column] = pd.to_datetime(frame[column], format="mixed", utc=True, errors="coerce")

    frame["severity"] = frame["severity"].str.lower()
    frame["threat_type"] = frame["threat_type"].str.lower()
    frame["indicator_type"] = frame["indicator_type"].str.lower()
    frame["severity_score"] = frame["severity"].map(SEVERITY_SCORE).fillna(1)
    frame["country"] = frame.apply(derive_country, axis=1)
    return frame


@st.cache_data(ttl=60, show_spinner=False)
def load_mongo_dashboard_data() -> dict[str, object]:
    return load_mongo_context(mongo_uri=DEFAULT_MONGO_URI, database_name=DEFAULT_MONGO_DB)


def normalize_sqlite_intel(frame: pd.DataFrame) -> pd.DataFrame:
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


def build_demo_workplace_observables(global_intel: pd.DataFrame) -> pd.DataFrame:
    columns = [
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
    if global_intel.empty:
        return pd.DataFrame(columns=columns)

    candidates = global_intel[
        (global_intel["threat_type"].astype(str) != "warninglist_context")
        & (global_intel["indicator_type"].isin(["url", "domain", "ip", "hash"]))
    ].head(8)
    rows = []
    now = pd.Timestamp.now(tz="UTC")
    users = ["finance.user@corp.local", "ops.engineer@corp.local", "helpdesk@corp.local", "analyst@corp.local"]
    assets = ["FIN-LAP-014", "OPS-WS-022", "HELPDESK-07", "SOC-SANDBOX-01"]
    for index, (_, indicator) in enumerate(candidates.iterrows()):
        rows.append(
            {
                "event_collection": "demo_workplace_logs",
                "event_id": f"demo-{index + 1}",
                "event_time": now - pd.Timedelta(minutes=18 * index),
                "user": users[index % len(users)],
                "asset": assets[index % len(assets)],
                "source_ip": f"10.10.{index + 4}.{20 + index}",
                "destination_ip": "",
                "observable_type": indicator["indicator_type"],
                "observable_value": indicator["indicator_value"],
                "field_path": "demo.proxy.url",
                "raw_summary": "In-memory demo event used only when real Mongo workplace logs are absent.",
            }
        )
    return pd.DataFrame(rows, columns=columns)


def build_intelligence_pipeline(global_frame: pd.DataFrame, mongo_context: dict[str, object]) -> dict[str, object]:
    mongo_global = mongo_context["global_indicators"]
    combined_global = pd.concat([normalize_sqlite_intel(global_frame), mongo_global], ignore_index=True)
    if not combined_global.empty:
        combined_global = combined_global.drop_duplicates(subset=["indicator_type", "indicator_value", "source"])

    real_workspace = mongo_context["workspace_observables"]
    # Workspace observables are always sourced from MongoDB now.
    # When no real workplace collection exists, `load_mongo_context` will seed a lightweight
    # demo collection into MongoDB (still drift_db) and then reload it.
    demo_mode = False
    workspace = real_workspace

    correlations = correlate_observables(combined_global, workspace)
    scored = score_correlations(correlations)
    anomalies = detect_workplace_anomalies(workspace)
    trends = forecast_threat_trends(combined_global)
    narrative = build_soc_narrative(scored, anomalies, trends)
    return {
        "mongo_seed": mongo_context.get("workplace_seed", {}),
        "combined_global": combined_global,
        "workspace_observables": workspace,
        "workspace_demo_mode": demo_mode,
        "correlations": correlations,
        "scored_correlations": scored,
        "anomalies": anomalies,
        "trends": trends,
        "narrative": narrative,
    }


def _normalize_ollama_host(raw: str | None) -> str:
    """Accept full URLs or common mistakes (port-only, host:port without scheme)."""
    default = "http://localhost:11434"
    if not raw or not str(raw).strip():
        return default
    h = str(raw).strip().rstrip("/")
    if h.isdigit():
        return f"http://localhost:{h}"
    if h.startswith(":") and h[1:].isdigit():
        return f"http://localhost{h}"
    if "://" not in h:
        if re.match(r"^[\w.-]+:\d+$", h):
            return f"http://{h}"
        if re.match(r"^\d+$", h):
            return f"http://localhost:{h}"
        return f"http://{h}" if h else default
    return h


OLLAMA_HOST = _normalize_ollama_host(os.getenv("OLLAMA_HOST", "http://localhost:11434"))
OLLAMA_MODEL = (os.getenv("OLLAMA_MODEL", "llama3.2:3b") or "llama3.2:3b").strip()


def _ollama_get_json(path: str, *, host: str, timeout: float = 6.0) -> dict[str, object]:
    base = _normalize_ollama_host(host)
    req = urllib.request.Request(f"{base.rstrip('/')}{path}", method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _ollama_chat(
    messages: list[dict[str, str]],
    *,
    host: str,
    model: str,
    temperature: float = 0.2,
) -> str:
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": temperature},
    }
    data = json.dumps(payload).encode("utf-8")
    base = _normalize_ollama_host(host)
    req = urllib.request.Request(
        f"{base.rstrip('/')}/api/chat",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise RuntimeError(
            "Could not reach Ollama. Start the Ollama app (or run `ollama serve`) and make sure the host is correct "
            f"({base}). ({exc})"
        ) from exc
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(f"Ollama request failed: {exc}") from exc

    message = body.get("message") or {}
    content = message.get("content") or body.get("response") or ""
    return str(content).strip()


def _fallback_playbook(context: dict[str, object]) -> str:
    threat = str(context.get("threat_type", "unknown"))
    obs_type = str(context.get("observable_type", "ioc"))
    value = str(context.get("observable_value", ""))
    risk = int(context.get("risk_score", 0) or 0)
    label = str(context.get("model_label", ""))

    lines = [
        f"You have a prioritized exposure: **{obs_type}** `{value}` (risk **{risk}/100**, label **{label}**, threat **{threat}**).",
        "",
        "### Step-by-step remediation (fallback playbook)",
        "1) **Contain**: block the indicator at the perimeter (DNS/URL filtering, firewall denylist) and disable user access if credentials may be exposed.",
        "2) **Preserve evidence**: export proxy/DNS/email logs + endpoint telemetry around the event time; keep hashes/URLs intact for IR.",
        "3) **Hunt laterally**: search for the same URL/domain/IP across endpoints, mailboxes, and auth logs; look for repeated downloads or beaconing.",
        "4) **Validate endpoints**: run an EDR scan / isolate the affected asset until clean; check browser extensions and scheduled tasks.",
        "5) **Credential hygiene**: if phishing/malware_download: force password reset + MFA enforcement for impacted accounts.",
        "6) **Verify elimination**: re-run correlation after changes; confirm no new hits and no successful connections to the indicator.",
        "",
        "_Tip: start Ollama to replace this fallback with a local LLM-generated plan tailored to your exact fields._",
    ]
    return "\n".join(lines)


def _risk_band(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _residual_risk(base_risk: int, steps: list[dict[str, object]] | None) -> int:
    """Reduce risk as mitigations are marked done (UI-only signal)."""
    base = int(base_risk or 0)
    if not steps:
        return max(0, min(100, base))
    total = max(1, len(steps))
    done = sum(1 for s in steps if bool(s.get("done")))
    # Each completed step reduces risk a bit; containment/verify carry more weight via the multiplier.
    weight = 0.12
    if any(s.get("id") == "contain" and bool(s.get("done")) for s in steps):
        weight += 0.06
    if any(s.get("id") == "verify" and bool(s.get("done")) for s in steps):
        weight += 0.06
    reduction = int(round(base * min(0.7, (done / total) * weight)))
    return max(0, min(100, base - reduction))


def _classify_intent(prompt: str) -> str:
    p = (prompt or "").strip().lower()
    if not p:
        return "next"
    if any(k in p for k in ["summarize", "summary", "tl;dr", "tldr", "brief"]):
        return "summarize"
    if any(k in p for k in ["why", "explain", "reason", "risk", "danger"]):
        return "explain_risk"
    if any(k in p for k in ["report", "write-up", "write up", "ticket", "incident note"]):
        return "report"
    if any(k in p for k in ["hunt", "search", "query", "kql", "splunk"]):
        return "hunt"
    if any(k in p for k in ["verify", "confirm", "done", "clean", "resolved"]):
        return "verify"
    if any(k in p for k in ["contain", "block", "isolate"]):
        return "contain"
    return "next"


def _guidance_engine(context: dict[str, object], *, detailed: bool) -> str:
    """Deterministic SOC guidance with no LLM dependency."""
    mode = str(context.get("mode", "unknown"))
    threat = str(context.get("threat_type", "unknown")).lower()
    obs_type = str(context.get("observable_type", "ioc")).lower()
    value = str(context.get("observable_value", "")).strip()
    risk = int(context.get("risk_score", 0) or 0)
    band = _risk_band(risk)
    user = str(context.get("user", "")).strip()
    asset = str(context.get("asset", "")).strip()
    reco = str(context.get("recommended_action", "")).strip()

    scope = []
    if asset:
        scope.append(f"asset **{asset}**")
    if user:
        scope.append(f"user **{user}**")
    scope_line = (", ".join(scope)) if scope else "your environment"

    def _pick(key: str, options: list[str]) -> str:
        seed = f"{mode}|{obs_type}|{value}|{key}"
        idx = int(hashlib.md5(seed.encode("utf-8")).hexdigest()[:8], 16) % max(1, len(options))
        return options[idx]

    ioc_hint = ""
    if obs_type == "url":
        ioc_hint = "Block URL + domain, and review download/redirect chain."
    elif obs_type == "domain":
        ioc_hint = "Block domain (DNS sinkhole) and watch for subdomain pivots."
    elif obs_type == "ip":
        ioc_hint = "Block IP at firewall/egress and check ASN/range pivots."
    elif obs_type == "hash":
        ioc_hint = "Block hash in EDR and hunt for file executions."

    summary = f"Priority exposure: **{obs_type}** `{value}` (risk **{risk}/100** • {band})."
    if threat and threat != "unknown":
        summary += f" Suspected: **{threat}**."
    if ioc_hint:
        summary += f" {ioc_hint}"

    def _bullets(items: list[str]) -> str:
        return "\n".join([f"- {item}" for item in items if item])

    def _step(n: int, title: str, bullets: list[str]) -> str:
        return f"{n}) **{title}**\n{_bullets(bullets)}"

    # Make steps differ per case by keying picks to observable+mode.
    def _pick_local(key: str, options: list[str]) -> str:
        return _pick(f"{obs_type}|{value}|{key}", options)

    payload_hint = ""
    if value:
        lower = value.lower()
        if lower.endswith(".sh") or ".sh?" in lower:
            payload_hint = "shell_script"
        elif lower.endswith(".exe") or lower.endswith(".msi"):
            payload_hint = "windows_binary"
        elif lower.endswith(".js") or lower.endswith(".vbs"):
            payload_hint = "script"

    # Identify a coarse playbook family.
    if any(k in threat for k in ["ransom", "encrypt"]):
        family = "ransomware"
    elif any(k in threat for k in ["botnet", "c2", "beacon"]):
        family = "botnet"
    elif any(k in threat for k in ["scanner", "scan", "brute", "bruteforce"]):
        family = "scanner"
    elif any(k in threat for k in ["phish", "credential"]):
        family = "phishing"
    elif any(k in threat for k in ["malware", "download", "trojan"]):
        family = "malware_download"
    else:
        family = "generic"

    # Case-specific containment.
    contain_title = _pick_local("contain_title", ["Contain", "Stop the bleed", "Immediate containment", "Block & isolate"])
    contain_sets = {
        "ip": [
            "Deny egress to the IP on firewall/proxy (both IPv4/IPv6 if applicable).",
            "Hunt for the IP in firewall/proxy logs and tag affected hosts/users.",
            "Pivot to ASN and expand blocks only with evidence (avoid over-blocking).",
        ],
        "domain": [
            "Sinkhole/deny the domain at DNS and block HTTP(S) at proxy.",
            "Enumerate internally seen subdomains; block high-risk pivots.",
            "Capture resolved IPs over the time window and block egress where needed.",
        ],
        "url": [
            "Block the full URL pattern at secure web gateway (path + query when possible).",
            "Also block the registrable domain to prevent path pivots.",
            "Capture redirect chain and final landing host for additional blocking.",
        ],
        "hash": [
            "Block the hash in EDR and quarantine any detected copies.",
            "Identify hosts where it executed and isolate them pending triage.",
            "Collect parent process + command line to tune detections.",
        ],
    }
    contain_bullets = contain_sets.get(obs_type, ["Block the indicator at the perimeter (DNS/proxy/firewall).", "Isolate impacted endpoints while triaging."])
    if scope:
        contain_bullets.append(f"Scope: {scope_line}.")
    else:
        contain_bullets.append("Scope: confirm impacted users/assets.")

    steps: list[str] = []
    steps.append(_step(1, contain_title, contain_bullets))

    n = 2
    if family == "phishing":
        steps.append(
            _step(
                n,
                _pick_local("ph_step2", ["Credential protection", "Identity containment", "Account remediation"]),
                [
                    _pick_local("ph_creds", ["Reset passwords for impacted accounts.", "Rotate credentials and revoke sessions.", "Force sign-out and reset credentials."]),
                    "Enforce MFA and revoke refresh tokens/sessions.",
                    "Review mailbox rules, forwarding, and OAuth app grants.",
                ],
            )
        )
        n += 1
        steps.append(
            _step(
                n,
                _pick_local("ph_step3", ["Email hunt", "Message cleanup", "Gateway pivot"]),
                [
                    "Search gateway/mail logs for sender/domain/URL and similar subjects.",
                    "Quarantine matching messages and block future sends.",
                    "If attachments exist: detonate/sandbox and block hashes.",
                ],
            )
        )
        n += 1
    elif family == "malware_download":
        endpoint_bullets = [
            f"Run EDR full scan on {('asset ' + asset) if asset else 'impacted endpoints'}.",
            _pick_local("ep_tree", ["Review process tree and command line for the download/execution.", "Inspect parent process + child processes spawned from the browser.", "Check script host usage and suspicious child processes."]),
            "Inspect persistence (scheduled tasks, run keys, services, autoruns).",
        ]
        if payload_hint == "shell_script":
            endpoint_bullets.insert(1, "Inspect PowerShell/bash history and scheduled tasks for script execution.")
        elif payload_hint == "windows_binary":
            endpoint_bullets.insert(1, "Check Defender/EDR quarantine and SmartScreen events for the binary.")
        elif payload_hint == "script":
            endpoint_bullets.insert(1, "Inspect script host execution (wscript/cscript/node) around event time.")

        net_bullets = []
        if obs_type == "domain":
            net_bullets = [
                "Hunt DNS queries for domain + subdomains; pivot on NXDOMAIN bursts.",
                "Check proxy for full URLs under that domain and capture redirect chain.",
                "Pivot to resolved IPs and block egress to the full set if malicious.",
            ]
        elif obs_type == "ip":
            net_bullets = [
                "Hunt firewall/proxy for outbound to the IP; pivot on ports + byte volume.",
                "Pivot to ASN / adjacent /24 range when there are multiple hits.",
                "Check for repeat beacon intervals (5m/10m/15m patterns).",
            ]
        elif obs_type == "hash":
            net_bullets = [
                "Use EDR hash search to find all endpoints that executed/contained it.",
                "Pivot from the binary to contacted domains/IPs in EDR network telemetry.",
                "Block related indicators discovered from network connections.",
            ]
        else:  # url
            net_bullets = [
                "Hunt proxy for exact URL and same registrable domain.",
                "Pivot on user-agent + referrer + redirect destinations.",
                "Check for downloads from the same hosting IP / path pattern.",
            ]

        steps.append(_step(n, _pick_local("mal_ep", ["Endpoint validation", "Host triage", "Execution review"]), endpoint_bullets))
        n += 1
        steps.append(_step(n, _pick_local("mal_net", ["Network pivot", "Outbound hunt", "C2 investigation"]), net_bullets))
        n += 1
    elif family == "ransomware":
        steps.append(
            _step(
                n,
                _pick_local("ran_step2", ["Isolate & triage", "Blast radius", "Lateral movement check"]),
                [
                    "Isolate impacted hosts immediately (EDR containment).",
                    "Check SMB/RDP/WinRM lateral movement from same source host/user.",
                    "Validate backups and last known-good restore points.",
                ],
            )
        )
        n += 1
        steps.append(
            _step(
                n,
                _pick_local("ran_step3", ["Tooling hunt", "Persistence check", "Kill chain mapping"]),
                [
                    "Hunt for encryption tooling (mass rename, vssadmin/bcdedit usage).",
                    "Check scheduled tasks/services for launchers and droppers.",
                    "Block discovered droppers/domains/IPs from the hunt.",
                ],
            )
        )
        n += 1
    elif family == "botnet":
        steps.append(
            _step(
                n,
                _pick_local("bot_step2", ["Beacon analysis", "C2 profiling", "Outbound profiling"]),
                [
                    "Look for periodic beacons (interval patterns; same dst port).",
                    "Pivot to additional infra (domains↔IPs) from DNS/proxy logs.",
                    "Isolate suspected infected endpoints and collect process listings.",
                ],
            )
        )
        n += 1
        steps.append(
            _step(
                n,
                _pick_local("bot_step3", ["Cleanup", "Persistence removal", "Reinfection prevention"]),
                [
                    "Remove persistence (autoruns, scheduled tasks, services).",
                    "Block full indicator set at egress and add EDR detections.",
                    "Monitor for reinfection attempts for 24–48h.",
                ],
            )
        )
        n += 1
    elif family == "scanner":
        steps.append(
            _step(
                n,
                _pick_local("scan_step2", ["Surface reduction", "Exposure triage", "WAF / rate-limit"]),
                [
                    "Identify targeted services/ports and confirm exposure is intended.",
                    "Apply rate limits/WAF rules and IP reputation blocks if applicable.",
                    "Patch/disable vulnerable services and rotate exposed credentials.",
                ],
            )
        )
        n += 1
        steps.append(
            _step(
                n,
                _pick_local("scan_step3", ["Detection tuning", "Noise reduction", "Exploit validation"]),
                [
                    "Detect repeat scanning patterns (URI fuzzing, auth failures).",
                    "Separate internet noise from real internal compromise signals.",
                    "Escalate only if exploitation indicators appear (webshell/new admin).",
                ],
            )
        )
        n += 1
    else:
        steps.append(
            _step(
                n,
                _pick_local("gen_step2", ["Evidence capture", "Triage data", "Log preservation"]),
                [
                    "Export DNS/Proxy/EDR/auth logs around event time.",
                    "Preserve request metadata, parent process, and artifacts if available.",
                    "Record first-seen/last-seen and deny/allow outcomes.",
                ],
            )
        )
        n += 1
        steps.append(
            _step(
                n,
                _pick_local("gen_step3", ["Environment hunt", "Scope expansion", "Pivot & correlate"]),
                [
                    f"Search for `{value}` across endpoints + network + auth + email.",
                    "Pivot on related indicators (domain↔url, ip range, hash family).",
                    "Identify additional affected users/assets.",
                ],
            )
        )
        n += 1

    steps.append(
        _step(
            n,
            _pick_local("assess_title", ["Assess impact", "Validate outcome", "Confirm exposure", "Outcome review"]),
            [
                f"Determine whether `{value}` was blocked or successful (allowed connection/download/auth).",
                "Identify first-seen vs last-seen hits and affected hosts/users.",
                "Confirm payload execution or credential abuse (if applicable).",
            ],
        )
    )
    n += 1

    if detailed and reco:
        steps.append(f"5) **Model recommendation**\n- {reco}")
        steps.append("6) **Eradicate + harden**\n- Patch vulnerable software, remove persistence, and tighten filtering rules.\n- Add detections for the indicator family and related TTPs.")
        steps.append("7) **Verify**\n- Re-run correlation and confirm hits drop to zero.\n- Monitor for reappearance for 24–48h.")
    else:
        steps.append(
            _step(
                n,
                _pick_local("erad_title", ["Eradicate + harden", "Cleanup & harden", "Close the gap", "Remediate"]),
                [
                    "Remove persistence, patch, and add detections/blocks for related indicators.",
                    (f"Prefer controls for {obs_type}: {ioc_hint}" if ioc_hint else ""),
                    _pick_local(
                        "erad_extra",
                        [
                            "Document rule changes and keep exceptions time-bound.",
                            "Update detections/playbooks for this threat family.",
                            "Confirm controls deployed to all edges (VPN/branch/cloud egress).",
                        ],
                    ),
                ],
            )
        )
        n += 1
        steps.append(
            _step(
                n,
                _pick_local("verify_title", ["Verify", "Confirm resolution", "Post-fix checks", "Validation"]),
                [
                    f"Re-run correlation and confirm no new hits in {scope_line}.",
                    "Watch for reappearance for 24–48h.",
                    _pick_local(
                        "verify_extra",
                        [
                            "Spot-check related indicators for the same pattern.",
                            "Confirm blocks are active in DNS + proxy + firewall (and EDR if applicable).",
                            "Ensure alerts are not too noisy after rule changes.",
                        ],
                    ),
                ],
            )
        )

    checks = [
        "- Indicator blocked in DNS + proxy + firewall (and EDR if applicable).",
        "- No successful connections/downloads after containment timestamp.",
        "- Affected endpoints scanned/isolated; no persistence artifacts remain.",
    ]
    if threat in {"phishing", "credential_phishing"} or "phish" in threat:
        checks.append("- Accounts reset + MFA enforced; sessions/tokens revoked.")
    checks.append("- Correlation risk score decreased and no new correlated exposures appear.")

    out = [
        summary,
        "",
        "### Next steps",
        *steps,
        "",
        "### Verification",
        *checks[: (5 if detailed else 4)],
    ]
    if context.get("soc_narrative"):
        out += ["", "### Context", str(context.get("soc_narrative"))]
    if mode and mode != "unknown":
        out += ["", f"_Focus mode: **{mode}**_"]
    return "\n".join(out)


def _guidance_chat_reply(
    context: dict[str, object],
    prompt: str,
    *,
    detailed: bool,
    style: str,
    steps: list[dict[str, object]] | None = None,
) -> str:
    intent = _classify_intent(prompt)
    base_risk = int(context.get("risk_score", 0) or 0)
    residual = _residual_risk(base_risk, steps)
    band = _risk_band(residual)
    value = str(context.get("observable_value", "")).strip()
    threat = str(context.get("threat_type", "unknown")).strip()
    scope = ", ".join([x for x in [str(context.get("asset", "")).strip(), str(context.get("user", "")).strip()] if x]) or "n/a"

    if intent == "summarize":
        if style == "Executive":
            return (
                f"**Status**: `{value}` • residual risk **{residual}/100** ({band}).\n\n"
                f"- **What**: {threat or 'ioc'} observed with highest priority in the current view.\n"
                f"- **Where**: {scope}.\n"
                "- **Action**: contain + validate endpoints, then verify no new hits.\n"
            )
        return (
            f"**IOC** `{value}` • **residual risk** **{residual}/100** ({band}) • **threat** `{threat}` • **scope** `{scope}`\n"
        )

    if intent == "explain_risk":
        return (
            f"### Why this is risky\n"
            f"- **Base risk**: {base_risk}/100 from correlation/model scoring.\n"
            f"- **Residual risk**: {residual}/100 ({band}) based on completed mitigations.\n"
            f"- **Drivers**: threat `{threat}`, confidence `{context.get('confidence')}`, severity `{context.get('severity')}`.\n"
            f"- **Scope**: {scope}.\n"
        )

    if intent == "report":
        return (
            "### Incident note (copy/paste)\n"
            f"- **Indicator**: {context.get('observable_type')} `{value}`\n"
            f"- **Threat**: `{threat}` • **Severity**: `{context.get('severity')}` • **Confidence**: {context.get('confidence')}\n"
            f"- **Risk**: base {base_risk}/100 → residual {residual}/100 ({band})\n"
            f"- **Scope**: asset/user: {scope}\n"
            f"- **Matched**: `{context.get('matched_indicator')}` ({context.get('matched_type')}) from `{context.get('source')}`\n"
            "- **Actions taken**: (tick items below)\n"
            + "\n".join([f"  - [{'x' if bool(s.get('done')) else ' '}] {s.get('label')}" for s in (steps or [])])
            + "\n- **Verification**: no new hits after containment; correlation risk down.\n"
        )

    if intent == "hunt":
        # Tool-agnostic "queries" so it varies and feels useful without hardcoding a SIEM.
        return (
            "### Hunt ideas\n"
            f"- **Proxy/DNS**: search for `{value}` and same registrable domain; pivot on user-agent and referrers.\n"
            f"- **EDR**: look for process tree that spawned the browser/download; pivot on file hash and parent process.\n"
            f"- **Auth**: check unusual logins for `{context.get('user')}` around `{context.get('event_time')}`.\n"
            "- **Network**: look for repeat beacons to same ASN / IP range if applicable.\n"
        )

    if intent == "verify":
        return (
            "### Verification checklist\n"
            "- No successful connections/downloads after containment timestamp.\n"
            "- Blocks effective across DNS/proxy/firewall.\n"
            "- Endpoint scan clean; no persistence.\n"
            "- Correlation risk decreased; no new correlated exposures.\n"
        )

    if intent == "contain":
        return (
            "### Containment checklist\n"
            "1) Block the indicator in DNS + proxy + firewall.\n"
            "2) Isolate impacted endpoint(s) in EDR.\n"
            "3) If user-linked: revoke sessions and reset creds if phishing suspected.\n"
            "4) Start a 1–2h watch for repeat hits.\n"
        )

    # Default: "next steps" but tailored by remaining checklist when available.
    if steps is None:
        ctx2 = dict(context)
        ctx2["risk_score"] = residual
        return _guidance_engine(ctx2, detailed=detailed)

    remaining = [s for s in steps if not bool(s.get("done"))]
    if remaining:
        ctx2 = dict(context)
        ctx2["risk_score"] = residual
        ctx2["recommended_action"] = f"Next: {', '.join([s['label'] for s in remaining[:2]])}."
        if style == "Ops":
            return (
                f"**Next** (residual {residual}/100): {remaining[0]['label']}\n"
                + (f"\n- After that: {remaining[1]['label']}" if len(remaining) > 1 else "")
            )
        return _guidance_engine(ctx2, detailed=detailed)

    return (
        f"All checklist steps are marked done. Residual risk is **{residual}/100** ({band}).\n\n"
        "Next: run verification (and then mark solved → next case).\n"
    )


def _build_threat_context(frame: pd.DataFrame, mongo_context: dict[str, object]) -> dict[str, object]:
    pipeline = build_intelligence_pipeline(frame, mongo_context)
    scored = pipeline.get("scored_correlations", pd.DataFrame())
    if isinstance(scored, pd.DataFrame) and not scored.empty:
        top = scored.sort_values(["risk_score", "confidence"], ascending=[False, False]).iloc[0].to_dict()
        return {
            "mode": "correlated_exposure",
            "observable_type": top.get("observable_type"),
            "observable_value": top.get("observable_value"),
            "matched_indicator": top.get("matched_indicator"),
            "matched_type": top.get("matched_type"),
            "source": top.get("source"),
            "threat_type": top.get("threat_type"),
            "severity": top.get("severity"),
            "confidence": int(top.get("confidence") or 0),
            "risk_score": int(top.get("risk_score") or 0),
            "model_label": top.get("model_label"),
            "recommended_action": top.get("recommended_action"),
            "user": top.get("user"),
            "asset": top.get("asset"),
            "event_collection": top.get("event_collection"),
            "event_time": str(top.get("event_time")),
            "soc_narrative": pipeline.get("narrative"),
        }

    combined = pipeline.get("combined_global", pd.DataFrame())
    if isinstance(combined, pd.DataFrame) and not combined.empty:
        sort_cols = ["severity_score", "confidence"]
        ascending = [False, False]
        if "risk_score" in combined.columns:
            sort_cols = ["risk_score", "severity_score", "confidence"]
            ascending = [False, False, False]
        hot = combined.sort_values(sort_cols, ascending=ascending).iloc[0]
        coarse_risk = int(float(hot.get("severity_score", 0) or 0) * 20)
        return {
            "mode": "global_hot_indicator",
            "observable_type": hot.get("indicator_type"),
            "observable_value": hot.get("indicator_value"),
            "source": hot.get("source"),
            "threat_type": hot.get("threat_type"),
            "severity": hot.get("severity"),
            "confidence": int(hot.get("confidence") or 0),
            "risk_score": min(100, max(0, coarse_risk)),
            "model_label": "Global priority (Mongo/SQLite)",
            "recommended_action": "Treat as high-signal IOC until disproven by internal evidence.",
            "user": "",
            "asset": "",
            "event_collection": hot.get("collection"),
            "event_time": "",
            "soc_narrative": pipeline.get("narrative"),
        }

    narrative = pipeline.get("narrative")
    if narrative:
        return {"mode": "narrative_only", "soc_narrative": narrative}

    return {"mode": "no_data"}


def _build_threat_queue(frame: pd.DataFrame, mongo_context: dict[str, object]) -> list[dict[str, object]]:
    """Return a ranked list of threat contexts (most dangerous first)."""
    pipeline = build_intelligence_pipeline(frame, mongo_context)
    scored = pipeline.get("scored_correlations", pd.DataFrame())
    out: list[dict[str, object]] = []

    if isinstance(scored, pd.DataFrame) and not scored.empty:
        topn = scored.sort_values(["risk_score", "confidence"], ascending=[False, False]).head(10)
        for _, row in topn.iterrows():
            r = row.to_dict()
            out.append(
                {
                    "mode": "correlated_exposure",
                    "observable_type": r.get("observable_type"),
                    "observable_value": r.get("observable_value"),
                    "matched_indicator": r.get("matched_indicator"),
                    "matched_type": r.get("matched_type"),
                    "source": r.get("source"),
                    "threat_type": r.get("threat_type"),
                    "severity": r.get("severity"),
                    "confidence": int(r.get("confidence") or 0),
                    "risk_score": int(r.get("risk_score") or 0),
                    "model_label": r.get("model_label"),
                    "recommended_action": r.get("recommended_action"),
                    "user": r.get("user"),
                    "asset": r.get("asset"),
                    "event_collection": r.get("event_collection"),
                    "event_time": str(r.get("event_time")),
                    "soc_narrative": pipeline.get("narrative"),
                }
            )

    combined = pipeline.get("combined_global", pd.DataFrame())
    if isinstance(combined, pd.DataFrame) and not combined.empty:
        # Some sources don't carry the UI helper columns; compute defensively.
        if "severity_score" not in combined.columns:
            combined = combined.copy()
            combined["severity"] = combined.get("severity", "").astype(str).str.lower()
            combined["severity_score"] = combined["severity"].map(SEVERITY_SCORE).fillna(1)
        if "confidence" in combined.columns:
            combined = combined.copy()
            combined["confidence"] = pd.to_numeric(combined["confidence"], errors="coerce").fillna(0).astype(int)
        else:
            combined = combined.copy()
            combined["confidence"] = 0

        sort_cols = ["severity_score", "confidence"]
        ascending = [False, False]
        if "risk_score" in combined.columns:
            sort_cols = ["risk_score", "severity_score", "confidence"]
            ascending = [False, False, False]
        topg = combined.sort_values(sort_cols, ascending=ascending).head(10)
        for _, row in topg.iterrows():
            sev_score = float(row.get("severity_score", 0) or 0)
            coarse_risk = int(sev_score * 20)
            out.append(
                {
                    "mode": "global_hot_indicator",
                    "observable_type": row.get("indicator_type"),
                    "observable_value": row.get("indicator_value"),
                    "source": row.get("source"),
                    "threat_type": row.get("threat_type"),
                    "severity": row.get("severity"),
                    "confidence": int(row.get("confidence") or 0),
                    "risk_score": min(100, max(0, coarse_risk)),
                    "model_label": "Global priority (Mongo/SQLite)",
                    "recommended_action": "Treat as high-signal IOC until disproven by internal evidence.",
                    "user": "",
                    "asset": "",
                    "event_collection": row.get("collection"),
                    "event_time": "",
                    "soc_narrative": pipeline.get("narrative"),
                }
            )

    # De-dup by mode + observable tuple, keep first occurrence (highest-ranked earlier).
    seen: set[tuple[str, str, str]] = set()
    deduped: list[dict[str, object]] = []
    for item in out:
        key = (str(item.get("mode")), str(item.get("observable_type")), str(item.get("observable_value")))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    deduped.sort(key=lambda d: int(d.get("risk_score", 0) or 0), reverse=True)
    return deduped[:10]


def _case_id(ctx: dict[str, object]) -> str:
    return f"{ctx.get('mode')}|{ctx.get('observable_type')}|{ctx.get('observable_value')}"


def _default_case_steps(ctx: dict[str, object]) -> list[dict[str, object]]:
    """A minimal SOC checklist; state lives in session_state and drives non-repetitive guidance."""
    threat = str(ctx.get("threat_type", "")).lower()
    steps = [
        {"id": "contain", "label": "Contain (block/isolate)", "done": False},
        {"id": "evidence", "label": "Preserve evidence (logs/artifacts)", "done": False},
        {"id": "hunt", "label": "Hunt across environment (users/assets)", "done": False},
    ]
    if "phish" in threat:
        steps.append({"id": "creds", "label": "Credential actions (reset/MFA/revoke sessions)", "done": False})
    steps += [
        {"id": "eradicate", "label": "Eradicate + harden (cleanup/detections)", "done": False},
        {"id": "verify", "label": "Verify (no new hits; risk down)", "done": False},
    ]
    return steps


def render_soc_copilot(frame: pd.DataFrame, mongo_context: dict[str, object]) -> None:
    """Minimal, non-chat assistant: pick a case, get tailored suggestions."""
    queue = _build_threat_queue(frame, mongo_context)
    if not queue:
        return

    with st.container(border=True):
        st.markdown("### Drift")
        st.caption("Pick one of the top cases to work on. Each case has its own risk and tailored steps.")

        def _label_case(i: int, ctx: dict[str, object]) -> str:
            risk = int(ctx.get("risk_score", 0) or 0)
            t = str(ctx.get("threat_type", "ioc"))
            v = str(ctx.get("observable_value", ""))[:72]
            return f"{i+1}. {risk}/100 • {t} • {v}"

        if "solved_case_ids" not in st.session_state:
            st.session_state.solved_case_ids = set()
        if "active_case_index" not in st.session_state:
            st.session_state.active_case_index = 0

        top_all = queue[:8]
        top = [c for c in top_all if _case_id(c) not in st.session_state.solved_case_ids][:5]
        if not top:
            st.success("All top cases are marked solved. Reset solved to review again.")
            if st.button("Reset solved", use_container_width=True):
                st.session_state.solved_case_ids = set()
                st.session_state.active_case_index = 0
                st.rerun()
            return

        labels = [_label_case(i, c) for i, c in enumerate(top)]
        # Keep user's current selection stable.
        st.session_state.active_case_index = min(int(st.session_state.active_case_index or 0), len(top) - 1)
        selected_index = st.selectbox(
            "Case",
            options=list(range(len(top))),
            format_func=lambda i: labels[i],
            index=int(st.session_state.active_case_index),
        )
        st.session_state.active_case_index = int(selected_index)
        ctx = top[int(selected_index)]
        cid = _case_id(ctx)

        action_row = st.columns([1.2, 0.8])
        if action_row[0].button("Mark solved → Next case", use_container_width=True):
            st.session_state.solved_case_ids.add(cid)
            st.session_state.active_case_index = min(int(selected_index), max(0, len(top) - 2))
            st.rerun()
        if action_row[1].button("Reset solved", use_container_width=True):
            st.session_state.solved_case_ids = set()
            st.session_state.active_case_index = 0
            st.rerun()

        if "simple_case_steps" not in st.session_state:
            st.session_state.simple_case_steps = {}
        if cid not in st.session_state.simple_case_steps:
            st.session_state.simple_case_steps[cid] = _default_case_steps(ctx)

        base_risk = int(ctx.get("risk_score", 0) or 0)
        band = _risk_band(base_risk)
        left, right = st.columns([1.05, 0.95])
        left.markdown(
            f"**Indicator**: {ctx.get('observable_type')} `{ctx.get('observable_value')}`  \n"
            f"**Threat**: `{ctx.get('threat_type')}` • **Risk**: **{base_risk}/100** ({band}) • **Confidence**: {ctx.get('confidence')}"
        )
        if ctx.get("asset") or ctx.get("user"):
            right.markdown(f"**Scope**: asset `{ctx.get('asset')}` • user `{ctx.get('user')}`")
        else:
            right.markdown("**Scope**: n/a")

        st.markdown("#### Suggested actions")
        st.markdown(_guidance_chat_reply(ctx, "next", detailed=False, style="Ops", steps=None))

        st.markdown("#### Steps to solve (per case)")
        steps = st.session_state.simple_case_steps[cid]
        for s in steps:
            s["done"] = st.checkbox(
                s["label"],
                value=bool(s.get("done")),
                key=f"simple_step_{cid}_{s['id']}",
            )
        st.session_state.simple_case_steps[cid] = steps
        done = sum(1 for s in steps if bool(s.get("done")))
        total = max(1, len(steps))
        resid = _residual_risk(base_risk, steps)
        st.caption(f"Progress: {done}/{total} • residual risk estimate: {resid}/100")
        st.markdown(_guidance_chat_reply(ctx, "next", detailed=False, style="Ops", steps=steps))

        quick = st.columns(5)
        if quick[0].button("Summarize", use_container_width=True, key=f"sum_{cid}"):
            st.markdown(_guidance_chat_reply(ctx, "summarize", detailed=False, style="Executive", steps=steps))
        if quick[1].button("Why risky?", use_container_width=True, key=f"why_{cid}"):
            st.markdown(_guidance_chat_reply(ctx, "why risky", detailed=False, style="Analyst", steps=steps))
        if quick[2].button("Contain", use_container_width=True, key=f"con_{cid}"):
            st.markdown(_guidance_chat_reply(ctx, "contain", detailed=False, style="Ops", steps=steps))
        if quick[3].button("Hunt", use_container_width=True, key=f"hunt_{cid}"):
            st.markdown(_guidance_chat_reply(ctx, "hunt", detailed=False, style="Analyst", steps=steps))
        if quick[4].button("Verify", use_container_width=True, key=f"ver_{cid}"):
            st.markdown(_guidance_chat_reply(ctx, "verify", detailed=False, style="Ops", steps=steps))


def derive_country(row: pd.Series) -> str:
    indicator_type = str(row.get("indicator_type", "")).lower()
    value = str(row.get("indicator_value", "")).lower().strip()

    if indicator_type == "ip":
        first_octet = extract_first_octet(value)
        if first_octet is None:
            return "Global"
        if first_octet < 32:
            return "United States"
        if first_octet < 64:
            return "Canada"
        if first_octet < 96:
            return "Germany"
        if first_octet < 128:
            return "United Kingdom"
        if first_octet < 160:
            return "Singapore"
        if first_octet < 192:
            return "Russia"
        if first_octet < 224:
            return "Brazil"
        return "Australia"

    base_value = value.split("/")[0]
    host = base_value.replace("http://", "").replace("https://", "").split("?")[0].split(":")[0]
    host_parts = [part for part in host.split(".") if part]

    if len(host_parts) >= 2:
        two_level = ".".join(host_parts[-2:])
        if two_level in TLD_COUNTRY_MAP:
            return TLD_COUNTRY_MAP[two_level]
        if host_parts[-1] in TLD_COUNTRY_MAP:
            return TLD_COUNTRY_MAP[host_parts[-1]]

    if any(token in value for token in ["office", "microsoft", "paypal", "amazon", "bank"]):
        return "United States"
    if "telegram" in value or "vpn" in value:
        return "Russia"
    if "invoice" in value or "parcel" in value or "dhl" in value:
        return "Germany"
    return "Global"


def extract_first_octet(value: str) -> int | None:
    parts = value.split(".")
    if len(parts) < 4:
        return None
    try:
        return int(parts[0])
    except ValueError:
        return None


def render_control_ribbon(frame: pd.DataFrame) -> tuple[dict[str, object], pd.DataFrame]:
    st.markdown('<div class="panel-title">Mission Controls</div>', unsafe_allow_html=True)
    top_cols = st.columns([1.1, 1.1, 1.15, 1.15, 1.15, 1.15])

    refresh_interval_minutes = top_cols[0].select_slider(
        "Feed Poll Interval",
        options=[5, 10, 15, 20, 30, 45, 60],
        value=15,
    )
    per_feed_limit = top_cols[1].select_slider(
        "Records Per Feed",
        options=[25, 50, 75, 100, 150, 200, 250],
        value=100,
    )

    refresh_summary = maybe_refresh_live_feeds(
        refresh_interval_minutes=refresh_interval_minutes,
        per_feed_limit=per_feed_limit,
    )

    threat_types = sorted(frame["threat_type"].dropna().unique().tolist())
    severities = sorted(frame["severity"].dropna().unique().tolist())
    sources = sorted(frame["source"].dropna().unique().tolist())

    selected_threat_types = top_cols[2].multiselect(
        "Threat Type",
        options=threat_types,
        default=threat_types,
    )
    selected_severities = top_cols[3].multiselect(
        "Severity",
        options=severities,
        default=severities,
    )
    selected_sources = top_cols[4].multiselect(
        "Source",
        options=sources,
        default=sources,
    )
    selected_indicator_types = top_cols[5].multiselect(
        "IOC Type",
        options=sorted(frame["indicator_type"].dropna().unique().tolist()),
        default=sorted(frame["indicator_type"].dropna().unique().tolist()),
    )

    filtered_frame = frame[
        frame["threat_type"].isin(selected_threat_types)
        & frame["severity"].isin(selected_severities)
        & frame["source"].isin(selected_sources)
        & frame["indicator_type"].isin(selected_indicator_types)
    ].copy()
    return refresh_summary, filtered_frame


def render_report_nav() -> str:
    st.markdown('<div class="report-nav-label">Report Pages</div>', unsafe_allow_html=True)
    return st.radio(
        "Report Pages",
        options=[
            "Overview",
            "IOC Explorer",
            "Geo Intel",
            "Feed Ops",
            "Workplace Mongo",
            "Correlation",
            "AI Modeling",
        ],
        horizontal=True,
        label_visibility="collapsed",
    )


def render_header(frame: pd.DataFrame, refresh_summary: dict[str, object]) -> None:
    hot_zone = frame.loc[frame["severity_score"].idxmax()] if not frame.empty else None
    headline = hot_zone["indicator_value"] if hot_zone is not None else "No indicators loaded"
    refreshed_at = str(refresh_summary.get("refreshed_at", "n/a")).replace("T", " ").replace("+00:00", " UTC")

    st.markdown(
        f"""
        <div class="hero-shell">
            <div class="hero-copy">
                <div class="eyebrow">CyberAI SOC Command Surface</div>
                <h1>CyberAI Global Threat Intelligence Dashboard</h1>
                <p>
                    Live IOC visibility with executive BI framing, cyber heat overlays,
                    geographic threat spread, and active feed telemetry.
                </p>
            </div>
            <div class="hero-focus">
                <div class="focus-label">Priority Indicator</div>
                <div class="focus-value">{headline}</div>
                <div class="focus-meta">Last refresh attempt: {refreshed_at}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("<div style='height: 0.75rem'></div>", unsafe_allow_html=True)
    with st.container(border=True):
        st.markdown("### Exports (CSV)")
        st.caption("Download raw outputs for reporting or integration.")
        c1, c2, c3, c4 = st.columns(4)
        c1.link_button("Global IOCs", "http://localhost:8000/export/global.csv", use_container_width=True)
        c2.link_button("Correlations", "http://localhost:8000/export/correlations.csv", use_container_width=True)
        c3.link_button("Anomalies", "http://localhost:8000/export/anomalies.csv", use_container_width=True)
        c4.link_button("Trends", "http://localhost:8000/export/trends.csv", use_container_width=True)


def render_metrics(frame: pd.DataFrame) -> None:
    total_indicators = len(frame)
    high_critical = len(frame[frame["severity"].isin(["high", "critical"])])
    phishing_total = len(frame[frame["threat_type"] == "phishing"])
    malware_total = len(frame[frame["threat_type"].str.contains("malware", na=False)])
    sources_total = frame["source"].nunique()
    avg_confidence = round(frame["confidence"].mean(), 1) if not frame.empty else 0

    cards = [
        ("Total Indicators", total_indicators, "Monitored global IOC inventory"),
        ("High / Critical", high_critical, "Priority triage queue"),
        ("Phishing Volume", phishing_total, "Credential abuse pressure"),
        ("Malware Volume", malware_total, "Payload-related detections"),
        ("Feed Sources", sources_total, "Active intelligence providers"),
        ("Avg Confidence", avg_confidence, "Signal quality baseline"),
    ]

    columns = st.columns(6)
    for column, (title, value, subtitle) in zip(columns, cards):
        column.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">{title}</div>
                <div class="metric-value">{value}</div>
                <div class="metric-subtitle">{subtitle}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_metric_cards(cards: list[tuple[str, object, str]], columns_count: int | None = None) -> None:
    columns = st.columns(columns_count or len(cards))
    for column, (title, value, subtitle) in zip(columns, cards):
        column.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">{html.escape(str(title))}</div>
                <div class="metric-value">{html.escape(str(value))}</div>
                <div class="metric-subtitle">{html.escape(str(subtitle))}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_refresh_status(refresh_summary: dict[str, object]) -> None:
    statuses = pd.DataFrame(get_refresh_status())
    st.markdown('<div class="panel-title">Live Feed Health</div>', unsafe_allow_html=True)

    top_cols = st.columns([1.2, 0.8, 0.8])
    top_cols[0].markdown(
        f"""
        <div class="status-chip">
            <span>Last Attempt</span>
            <strong>{str(refresh_summary.get("refreshed_at", "n/a")).replace("T", " ").replace("+00:00", " UTC")}</strong>
        </div>
        """,
        unsafe_allow_html=True,
    )
    top_cols[1].markdown(
        f'<div class="status-chip"><span>Inserted</span><strong>{int(refresh_summary.get("inserted", 0))}</strong></div>',
        unsafe_allow_html=True,
    )
    top_cols[2].markdown(
        f'<div class="status-chip"><span>Updated</span><strong>{int(refresh_summary.get("updated", 0))}</strong></div>',
        unsafe_allow_html=True,
    )

    if statuses.empty:
        st.info("No live feed refresh has run yet.")
        return

    render_dark_table(
        statuses,
        title="Feed Health Matrix",
        subtitle="Live polling status, refresh times, and current feed execution metadata.",
        max_rows=8,
        height=320,
    )


def render_refresh_table_only() -> None:
    statuses = pd.DataFrame(get_refresh_status())
    if statuses.empty:
        st.info("No live feed refresh has run yet.")
        return
    render_dark_table(
        statuses,
        title="Feed Status Log",
        subtitle="Operational feed refresh history and last successful polling metadata.",
        max_rows=12,
        height=360,
    )


def render_search_results(frame: pd.DataFrame) -> None:
    st.markdown('<div class="panel-title">Threat Lookup</div>', unsafe_allow_html=True)
    search_value = st.text_input(
        "Search by URL, IP, Domain, or Hash",
        placeholder="Search IOC values, infrastructure, malware sample hashes, or feed artifacts",
        label_visibility="collapsed",
    ).strip()

    if search_value:
        results = frame[frame["indicator_value"].str.contains(search_value, case=False, na=False)].copy()
        st.caption(f"Matches: {len(results)}")
        if results.empty:
            st.warning("No matching indicators found.")
        else:
            render_dark_table(
                format_indicator_table(results),
                title="Threat Lookup Results",
                subtitle="Search hits across visible indicators.",
                max_rows=10,
                height=420,
            )


def render_explorer_table(frame: pd.DataFrame) -> None:
    explorer_frame = format_indicator_table(frame)
    render_dark_table(
        explorer_frame,
        title="Indicator Explorer",
        subtitle="Filtered indicators with source, severity, geo context, and last-seen timestamp.",
        max_rows=14,
        height=560,
    )


def format_indicator_table(frame: pd.DataFrame) -> pd.DataFrame:
    table = frame[
        [
            "indicator_type",
            "indicator_value",
            "threat_type",
            "source",
            "confidence",
            "severity",
            "country",
            "last_seen",
        ]
    ].copy()
    table.columns = [
        "Type",
        "Value",
        "Threat Type",
        "Source",
        "Confidence",
        "Severity",
        "Geo",
        "Last Seen",
    ]
    table["Last Seen"] = table["Last Seen"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return table


def build_table_html(frame: pd.DataFrame, max_rows: int = 14) -> str:
    table = format_indicator_table(frame).head(max_rows).copy()

    severity_class_map = {
        "critical": "sev-critical",
        "high": "sev-high",
        "medium": "sev-medium",
        "low": "sev-low",
    }
    type_class_map = {
        "url": "ioc-url",
        "domain": "ioc-domain",
        "ip": "ioc-ip",
        "hash": "ioc-hash",
    }

    rows_html: list[str] = []
    for _, row in table.iterrows():
        severity_value = str(row["Severity"]).lower()
        type_value = str(row["Type"]).lower()
        severity_class = severity_class_map.get(severity_value, "sev-low")
        type_class = type_class_map.get(type_value, "ioc-domain")
        rows_html.append(
            f"""
            <tr>
                <td><span class="ioc-pill {type_class}">{html.escape(str(row["Type"]).upper())}</span></td>
                <td class="ioc-value" title="{html.escape(str(row["Value"]))}">{html.escape(str(row["Value"]))}</td>
                <td>{html.escape(str(row["Threat Type"]).replace("_", " ").title())}</td>
                <td>{html.escape(str(row["Source"]))}</td>
                <td class="confidence-cell">{html.escape(str(row["Confidence"]))}</td>
                <td><span class="severity-pill {severity_class}">{html.escape(str(row["Severity"]).title())}</span></td>
                <td>{html.escape(str(row["Geo"]))}</td>
                <td class="timestamp-cell">{html.escape(str(row["Last Seen"]))}</td>
            </tr>
            """
        )

    return f"""
    <style>
        body {{
            margin: 0;
            background: transparent;
            font-family: "Segoe UI", Arial, sans-serif;
            color: {CYBER_COLORS["text"]};
        }}
        .ioc-table-shell {{
            background: linear-gradient(180deg, rgba(14, 23, 36, 0.98), rgba(9, 16, 27, 0.98));
            border: 1px solid rgba(255,255,255,0.07);
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 20px 44px rgba(0,0,0,0.28);
        }}
        .ioc-table-header {{
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 1rem;
            padding: 1rem 1.15rem 0.9rem 1.15rem;
            border-bottom: 1px solid rgba(255,255,255,0.06);
            background: linear-gradient(90deg, rgba(15, 31, 47, 0.94), rgba(10, 20, 34, 0.94));
        }}
        .ioc-table-title {{
            font-size: 1rem;
            font-weight: 700;
            color: {CYBER_COLORS["accent"]};
            letter-spacing: 0.02em;
        }}
        .ioc-table-subtitle {{
            font-size: 0.82rem;
            color: {CYBER_COLORS["muted"]};
            margin-top: 0.28rem;
        }}
        .ioc-table-meta {{
            color: {CYBER_COLORS["muted"]};
            font-size: 0.8rem;
            white-space: nowrap;
            padding-top: 0.15rem;
        }}
        .ioc-table-wrap {{
            overflow-x: auto;
        }}
        .ioc-table {{
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
        }}
        .ioc-table thead th {{
            text-align: left;
            font-size: 0.74rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #7fa0b9;
            padding: 0.82rem 0.95rem;
            background: rgba(255,255,255,0.025);
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }}
        .ioc-table tbody tr {{
            border-bottom: 1px solid rgba(255,255,255,0.045);
            transition: background 0.18s ease;
        }}
        .ioc-table tbody tr:hover {{
            background: rgba(23, 192, 235, 0.06);
        }}
        .ioc-table tbody td {{
            padding: 0.84rem 0.95rem;
            color: #e7f1fb;
            font-size: 0.9rem;
            vertical-align: middle;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        .ioc-table th:nth-child(1), .ioc-table td:nth-child(1) {{ width: 10%; }}
        .ioc-table th:nth-child(2), .ioc-table td:nth-child(2) {{ width: 34%; }}
        .ioc-table th:nth-child(3), .ioc-table td:nth-child(3) {{ width: 15%; }}
        .ioc-table th:nth-child(4), .ioc-table td:nth-child(4) {{ width: 13%; }}
        .ioc-table th:nth-child(5), .ioc-table td:nth-child(5) {{ width: 9%; }}
        .ioc-table th:nth-child(6), .ioc-table td:nth-child(6) {{ width: 10%; }}
        .ioc-table th:nth-child(7), .ioc-table td:nth-child(7) {{ width: 12%; }}
        .ioc-table th:nth-child(8), .ioc-table td:nth-child(8) {{ width: 15%; }}
        .ioc-value {{
            font-family: Consolas, Monaco, "Courier New", monospace;
            color: #f4fbff;
        }}
        .confidence-cell, .timestamp-cell {{
            color: #bdd1e1;
        }}
        .ioc-pill, .severity-pill {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 74px;
            padding: 0.34rem 0.6rem;
            border-radius: 999px;
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            border: 1px solid transparent;
        }}
        .ioc-url {{
            color: #63d7ff;
            background: rgba(23, 192, 235, 0.12);
            border-color: rgba(23, 192, 235, 0.28);
        }}
        .ioc-domain {{
            color: #7ef7c5;
            background: rgba(20, 241, 149, 0.12);
            border-color: rgba(20, 241, 149, 0.24);
        }}
        .ioc-ip {{
            color: #ffd166;
            background: rgba(255, 176, 32, 0.12);
            border-color: rgba(255, 176, 32, 0.26);
        }}
        .ioc-hash {{
            color: #d1b3ff;
            background: rgba(162, 89, 255, 0.12);
            border-color: rgba(162, 89, 255, 0.26);
        }}
        .sev-critical {{
            color: #fff2f5;
            background: linear-gradient(90deg, rgba(255,45,85,0.82), rgba(255,76,76,0.7));
            border-color: rgba(255,255,255,0.12);
            box-shadow: 0 0 18px rgba(255,45,85,0.18);
        }}
        .sev-high {{
            color: #fff7f0;
            background: linear-gradient(90deg, rgba(255,111,60,0.72), rgba(255,176,32,0.58));
            border-color: rgba(255,255,255,0.12);
        }}
        .sev-medium {{
            color: #fffbe8;
            background: rgba(255, 176, 32, 0.18);
            border-color: rgba(255, 176, 32, 0.28);
        }}
        .sev-low {{
            color: #dffcf1;
            background: rgba(20, 241, 149, 0.12);
            border-color: rgba(20, 241, 149, 0.22);
        }}
    </style>
    <div class="ioc-table-shell">
        <div class="ioc-table-header">
            <div>
                <div class="ioc-table-title">Real-Time Threat Feed</div>
                <div class="ioc-table-subtitle">Curated live indicators prioritized for SOC triage and executive review.</div>
            </div>
            <div class="ioc-table-meta">{min(len(frame), max_rows)} of {len(frame)} indicators shown</div>
        </div>
        <div class="ioc-table-wrap">
            <table class="ioc-table">
                <thead>
                    <tr>
                        <th>IOC Type</th>
                        <th>Indicator Value</th>
                        <th>Threat Type</th>
                        <th>Source</th>
                        <th>Confidence</th>
                        <th>Severity</th>
                        <th>Geo</th>
                        <th>Last Seen</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows_html)}
                </tbody>
            </table>
        </div>
    </div>
    """


def render_table(frame: pd.DataFrame) -> None:
    components.html(build_table_html(frame), height=520, scrolling=False)


def build_dark_table_html(
    frame: pd.DataFrame,
    title: str,
    subtitle: str = "",
    max_rows: int = 10,
) -> str:
    table = frame.head(max_rows).copy()
    columns = list(table.columns)

    rows_html: list[str] = []
    for _, row in table.iterrows():
        cells = "".join(
            f'<td title="{html.escape(str(value))}">{html.escape(str(value))}</td>'
            for value in row.tolist()
        )
        rows_html.append(f"<tr>{cells}</tr>")

    header_html = "".join(f"<th>{html.escape(str(column))}</th>" for column in columns)
    subtitle_html = f'<div class="dark-table-subtitle">{html.escape(subtitle)}</div>' if subtitle else ""

    return f"""
    <style>
        body {{
            margin: 0;
            background: transparent;
            font-family: "Segoe UI", Arial, sans-serif;
            color: {CYBER_COLORS["text"]};
        }}
        .dark-table-shell {{
            background: linear-gradient(180deg, rgba(14, 23, 36, 0.98), rgba(9, 16, 27, 0.98));
            border: 1px solid rgba(255,255,255,0.07);
            border-radius: 18px;
            overflow: hidden;
            box-shadow: 0 20px 44px rgba(0,0,0,0.22);
        }}
        .dark-table-head {{
            padding: 0.95rem 1rem 0.8rem 1rem;
            border-bottom: 1px solid rgba(255,255,255,0.06);
            background: linear-gradient(90deg, rgba(15, 31, 47, 0.94), rgba(10, 20, 34, 0.94));
        }}
        .dark-table-title {{
            color: {CYBER_COLORS["accent"]};
            font-size: 0.98rem;
            font-weight: 700;
        }}
        .dark-table-subtitle {{
            margin-top: 0.24rem;
            color: {CYBER_COLORS["muted"]};
            font-size: 0.8rem;
        }}
        .dark-table-wrap {{
            overflow-x: auto;
        }}
        .dark-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        .dark-table thead th {{
            text-align: left;
            font-size: 0.73rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #7fa0b9;
            padding: 0.78rem 0.9rem;
            background: rgba(255,255,255,0.025);
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }}
        .dark-table tbody td {{
            padding: 0.78rem 0.9rem;
            color: #e7f1fb;
            font-size: 0.88rem;
            border-bottom: 1px solid rgba(255,255,255,0.045);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .dark-table tbody tr:hover {{
            background: rgba(23, 192, 235, 0.06);
        }}
    </style>
    <div class="dark-table-shell">
        <div class="dark-table-head">
            <div class="dark-table-title">{html.escape(title)}</div>
            {subtitle_html}
        </div>
        <div class="dark-table-wrap">
            <table class="dark-table">
                <thead><tr>{header_html}</tr></thead>
                <tbody>{''.join(rows_html)}</tbody>
            </table>
        </div>
    </div>
    """


def render_dark_table(
    frame: pd.DataFrame,
    title: str,
    subtitle: str = "",
    max_rows: int = 10,
    height: int = 360,
) -> None:
    components.html(
        build_dark_table_html(frame, title=title, subtitle=subtitle, max_rows=max_rows),
        height=height,
        scrolling=False,
    )


def render_map_and_regions(frame: pd.DataFrame) -> None:
    left_col, right_col = st.columns([1.8, 1])
    geo_frame = (
        frame.groupby("country", as_index=False)
        .agg(threat_count=("id", "count"), avg_confidence=("confidence", "mean"), max_severity=("severity_score", "max"))
    )
    # "Global" is a fallback bucket when country can't be derived; don't let it dominate visuals.
    geo_frame = geo_frame[geo_frame["country"].astype(str) != "Global"].copy()
    if geo_frame.empty:
        st.info("Not enough geographic data to render the map yet.")
        return
    geo_frame["lat"] = geo_frame["country"].map(lambda name: COUNTRY_COORDS.get(name, COUNTRY_COORDS["Global"])[0])
    geo_frame["lon"] = geo_frame["country"].map(lambda name: COUNTRY_COORDS.get(name, COUNTRY_COORDS["Global"])[1])
    # Prevent a single region from visually dominating the entire map.
    # Use sqrt scaling + hard cap for stable bubble sizes.
    bubble = (geo_frame["threat_count"].fillna(0).clip(lower=0).astype(float) ** 0.5) * 6.0
    geo_frame["bubble_size"] = bubble.clip(lower=6.0, upper=42.0)

    with left_col:
        st.markdown('<div class="panel-title">Global Threat Pressure Map</div>', unsafe_allow_html=True)
        figure = go.Figure(
            data=[
                go.Scattergeo(
                    lon=geo_frame["lon"],
                    lat=geo_frame["lat"],
                    text=geo_frame["country"],
                    customdata=geo_frame[["threat_count", "avg_confidence"]],
                    mode="markers",
                    marker=dict(
                        size=geo_frame["bubble_size"],
                        color=geo_frame["max_severity"],
                        colorscale=[
                            [0.0, "#17c0eb"],
                            [0.35, "#14f195"],
                            [0.7, "#ffb020"],
                            [1.0, "#ff2d55"],
                        ],
                        line=dict(width=1, color="#d9f3ff"),
                        opacity=0.88,
                        sizemode="area",
                    ),
                    hovertemplate="<b>%{text}</b><br>Threats: %{customdata[0]}<br>Avg confidence: %{customdata[1]:.1f}<extra></extra>",
                )
            ]
        )
        figure.update_layout(
            margin=dict(l=0, r=0, t=0, b=0),
            paper_bgcolor="rgba(0,0,0,0)",
            geo=dict(
                bgcolor="rgba(0,0,0,0)",
                showframe=False,
                showcoastlines=True,
                coastlinecolor="#284056",
                projection_type="natural earth",
                landcolor="#0f2233",
                oceancolor="#081521",
                showland=True,
                showocean=True,
                lakecolor="#081521",
                countrycolor="#284056",
            ),
        )
        st.plotly_chart(figure, use_container_width=True)

    with right_col:
        st.markdown('<div class="panel-title">Regional Hotspots</div>', unsafe_allow_html=True)
        region_board = geo_frame.sort_values(["threat_count", "avg_confidence"], ascending=[False, False]).head(8)
        render_dark_table(
            region_board[["country", "threat_count", "avg_confidence"]].rename(
                columns={"country": "Region", "threat_count": "Threats", "avg_confidence": "Avg Confidence"}
            ),
            title="Regional Hotspots",
            subtitle="Highest concentration regions from the current filtered threat picture.",
            max_rows=8,
            height=360,
        )


def render_charts(frame: pd.DataFrame) -> None:
    top_left, top_right = st.columns(2)
    bottom_left, bottom_right = st.columns(2)

    if frame.empty:
        st.info("No chart data is available for the current filters.")
        return

    threats_by_type = (
        frame.groupby("threat_type", as_index=False)
        .agg(threat_count=("id", "count"), avg_confidence=("confidence", "mean"))
        .sort_values("threat_count", ascending=False)
        .head(10)
    )
    severity_distribution = frame["severity"].value_counts().reset_index()
    severity_distribution.columns = ["severity", "count"]
    daily_trend = (
        frame.assign(created_day=frame["created_at"].dt.date)
        .groupby("created_day", as_index=False)
        .agg(threat_count=("id", "count"), avg_confidence=("confidence", "mean"))
    )
    source_mix = frame["source"].value_counts().reset_index().head(8)
    source_mix.columns = ["source", "count"]

    with top_left:
        st.markdown('<div class="panel-title">Threat Type Distribution</div>', unsafe_allow_html=True)
        fig = px.bar(
            threats_by_type,
            x="threat_count",
            y="threat_type",
            orientation="h",
            color="avg_confidence",
            color_continuous_scale=["#17c0eb", "#14f195", "#ffb020", "#ff2d55"],
        )
        fig.update_layout(
            margin=dict(l=0, r=0, t=0, b=0),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color=CYBER_COLORS["text"]),
            coloraxis_showscale=False,
            xaxis=dict(showgrid=True, gridcolor=CYBER_COLORS["grid"]),
            yaxis=dict(showgrid=False, categoryorder="total ascending"),
        )
        st.plotly_chart(fig, use_container_width=True)

    with top_right:
        st.markdown('<div class="panel-title">Severity Split</div>', unsafe_allow_html=True)
        fig = px.pie(
            severity_distribution,
            values="count",
            names="severity",
            hole=0.62,
            color="severity",
            color_discrete_map={
                "low": "#17c0eb",
                "medium": "#14f195",
                "high": "#ffb020",
                "critical": "#ff2d55",
            },
        )
        fig.update_layout(
            margin=dict(l=0, r=0, t=0, b=0),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color=CYBER_COLORS["text"]),
            legend=dict(orientation="h", y=-0.08),
        )
        st.plotly_chart(fig, use_container_width=True)

    with bottom_left:
        st.markdown('<div class="panel-title">Threat Intake Timeline</div>', unsafe_allow_html=True)
        fig = go.Figure()
        fig.add_trace(
            go.Scatter(
                x=daily_trend["created_day"],
                y=daily_trend["threat_count"],
                mode="lines+markers",
                line=dict(color="#17c0eb", width=3),
                marker=dict(size=8, color="#14f195"),
                fill="tozeroy",
                fillcolor="rgba(23,192,235,0.12)",
                name="Threat Count",
            )
        )
        fig.update_layout(
            margin=dict(l=0, r=0, t=0, b=0),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color=CYBER_COLORS["text"]),
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor=CYBER_COLORS["grid"]),
        )
        st.plotly_chart(fig, use_container_width=True)

    with bottom_right:
        st.markdown('<div class="panel-title">Source Contribution</div>', unsafe_allow_html=True)
        fig = px.treemap(
            source_mix,
            path=["source"],
            values="count",
            color="count",
            color_continuous_scale=["#102435", "#17c0eb", "#14f195", "#ff2d55"],
        )
        fig.update_layout(
            margin=dict(l=0, r=0, t=0, b=0),
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color=CYBER_COLORS["text"]),
            coloraxis_showscale=False,
        )
        st.plotly_chart(fig, use_container_width=True)


def render_overview_page(frame: pd.DataFrame, refresh_summary: dict[str, object]) -> None:
    render_header(frame, refresh_summary)
    render_metrics(frame)
    st.markdown("<div style='height: 1rem'></div>", unsafe_allow_html=True)

    top_left, top_right = st.columns([1.35, 1])
    with top_left:
        render_search_results(frame)
        render_table(frame)
    with top_right:
        render_refresh_status(refresh_summary)

    st.markdown("<div style='height: 1rem'></div>", unsafe_allow_html=True)
    render_charts(frame)


def render_ioc_explorer_page(frame: pd.DataFrame) -> None:
    st.markdown(
        """
        <div class="page-hero">
            <div>
                <div class="eyebrow">Report Page</div>
                <h2>IOC Explorer</h2>
                <p>Deep-dive into indicator inventory, search results, severity mix, and source relationships.</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    upper_left, upper_right = st.columns([1.3, 1])
    with upper_left:
        render_search_results(frame)
        render_explorer_table(frame)
    with upper_right:
        threat_mix = frame["threat_type"].value_counts().reset_index()
        threat_mix.columns = ["Threat Type", "Count"]
        severity_mix = frame["severity"].value_counts().reset_index()
        severity_mix.columns = ["Severity", "Count"]
        render_dark_table(
            threat_mix,
            title="Threat Mix",
            subtitle="Current distribution of threat categories in the filtered view.",
            max_rows=10,
            height=280,
        )
        st.markdown('<div style="height: 1rem"></div>', unsafe_allow_html=True)
        render_dark_table(
            severity_mix,
            title="Severity Mix",
            subtitle="Current severity balance across visible indicators.",
            max_rows=6,
            height=230,
        )


def render_geo_page(frame: pd.DataFrame) -> None:
    st.markdown(
        """
        <div class="page-hero">
            <div>
                <div class="eyebrow">Report Page</div>
                <h2>Geo Intel</h2>
                <p>Regional threat concentration, country-level pressure mapping, and geographic prioritization.</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    render_map_and_regions(frame)
    st.markdown("<div style='height: 1rem'></div>", unsafe_allow_html=True)
    geo_frame = frame[frame["country"].astype(str) != "Global"].copy()
    geo_summary = (
        geo_frame.groupby(["country", "severity"], as_index=False)
        .agg(threat_count=("id", "count"))
        .sort_values(["threat_count"], ascending=False)
    )
    left, right = st.columns(2)
    with left:
        render_dark_table(
            geo_summary.rename(
                columns={"country": "Region", "severity": "Severity", "threat_count": "Threat Count"}
            ),
            title="Regional Severity Matrix",
            subtitle="Cross-section of regions and severities for current threat concentration.",
            max_rows=12,
            height=460,
        )
    with right:
        region_counts = geo_frame["country"].value_counts().reset_index().head(10)
        region_counts.columns = ["country", "count"]
        fig = px.bar(
            region_counts,
            x="count",
            y="country",
            orientation="h",
            color="count",
            color_continuous_scale=["#102435", "#17c0eb", "#14f195", "#ff2d55"],
        )
        fig.update_layout(
            margin=dict(l=0, r=0, t=0, b=0),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color=CYBER_COLORS["text"]),
            coloraxis_showscale=False,
            yaxis=dict(categoryorder="total ascending"),
        )
        st.markdown('<div class="panel-title">Top Regions by Threat Count</div>', unsafe_allow_html=True)
        st.plotly_chart(fig, use_container_width=True)


def render_feed_ops_page(frame: pd.DataFrame, refresh_summary: dict[str, object]) -> None:
    st.markdown(
        """
        <div class="page-hero">
            <div>
                <div class="eyebrow">Report Page</div>
                <h2>Feed Operations</h2>
                <p>Refresh telemetry, source contribution, ingestion cadence, and operational feed monitoring.</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    top_left, top_right = st.columns([1, 1.25])
    with top_left:
        render_refresh_status(refresh_summary)
    with top_right:
        render_refresh_table_only()
    st.markdown("<div style='height: 1rem'></div>", unsafe_allow_html=True)

    statuses = pd.DataFrame(get_refresh_status())
    if statuses.empty:
        st.info("No feed telemetry available yet.")
        return

    for col in ["inserted_count", "updated_count", "total_fetched"]:
        statuses[col] = pd.to_numeric(statuses.get(col), errors="coerce").fillna(0).astype(int)

    statuses["last_success_at"] = pd.to_datetime(statuses.get("last_success_at"), utc=True, errors="coerce")
    statuses["last_refresh_at"] = pd.to_datetime(statuses.get("last_refresh_at"), utc=True, errors="coerce")
    now = pd.Timestamp.now(tz="UTC")
    statuses["minutes_since_success"] = (
        (now - statuses["last_success_at"]).dt.total_seconds() / 60
    ).fillna(99999).astype(int)

    left, right = st.columns([1.2, 1])
    with left:
        st.markdown('<div class="panel-title">Per-Feed Intake (last run)</div>', unsafe_allow_html=True)
        intake = statuses[["feed_name", "inserted_count", "updated_count"]].copy()
        intake = intake.melt(id_vars=["feed_name"], var_name="metric", value_name="count")
        fig = px.bar(
            intake,
            x="feed_name",
            y="count",
            color="metric",
            barmode="group",
            color_discrete_map={
                "inserted_count": CYBER_COLORS["accent_2"],
                "updated_count": CYBER_COLORS["accent"],
            },
        )
        fig.update_layout(
            margin=dict(l=0, r=0, t=0, b=0),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color=CYBER_COLORS["text"]),
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor=CYBER_COLORS["grid"]),
            legend=dict(orientation="h", y=-0.18),
        )
        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.markdown('<div class="panel-title">Feed Freshness</div>', unsafe_allow_html=True)
        freshness = statuses[["feed_name", "minutes_since_success", "status"]].sort_values("minutes_since_success")
        fig = px.bar(
            freshness,
            x="minutes_since_success",
            y="feed_name",
            orientation="h",
            color="status",
            color_discrete_map={
                "success": CYBER_COLORS["accent_2"],
                "warning": CYBER_COLORS["warn"],
                "failed": CYBER_COLORS["high"],
                "error": CYBER_COLORS["critical"],
            },
        )
        fig.update_layout(
            margin=dict(l=0, r=0, t=0, b=0),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color=CYBER_COLORS["text"]),
            xaxis=dict(showgrid=True, gridcolor=CYBER_COLORS["grid"]),
            yaxis=dict(showgrid=False),
            legend=dict(orientation="h", y=-0.18),
        )
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("<div style='height: 1rem'></div>", unsafe_allow_html=True)
    st.markdown('<div class="panel-title">Operational Notes</div>', unsafe_allow_html=True)
    notes = statuses[["feed_name", "status", "message", "total_fetched", "last_refresh_at", "last_success_at"]].copy()
    notes["last_refresh_at"] = notes["last_refresh_at"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("n/a")
    notes["last_success_at"] = notes["last_success_at"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("n/a")
    render_dark_table(
        notes,
        title="Feed Execution Summary",
        subtitle="Status, last success, last refresh attempt, and any provider errors/quotas.",
        max_rows=12,
        height=380,
    )


def format_mongo_global_table(frame: pd.DataFrame) -> pd.DataFrame:
    if frame.empty:
        return pd.DataFrame()
    table = frame[["indicator_type", "indicator_value", "source", "threat_type", "confidence", "severity", "collection"]].copy()
    table.columns = ["Type", "Indicator", "Source", "Threat", "Confidence", "Severity", "Collection"]
    return table.head(250)


def format_workspace_table(frame: pd.DataFrame) -> pd.DataFrame:
    if frame.empty:
        return pd.DataFrame()
    table = frame[
        [
            "event_collection",
            "event_time",
            "user",
            "asset",
            "observable_type",
            "observable_value",
            "field_path",
        ]
    ].copy()
    table["event_time"] = pd.to_datetime(table["event_time"], format="mixed", utc=True, errors="coerce").dt.strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    table.columns = ["Collection", "Time", "User", "Asset", "Type", "Observable", "Field"]
    return table.head(250)


def format_correlation_table(frame: pd.DataFrame) -> pd.DataFrame:
    if frame.empty:
        return pd.DataFrame()
    table = frame[
        [
            "risk_score",
            "model_label",
            "event_time",
            "asset",
            "user",
            "observable_value",
            "source",
            "threat_type",
            "severity",
            "recommended_action",
        ]
    ].copy()
    table["event_time"] = pd.to_datetime(table["event_time"], format="mixed", utc=True, errors="coerce").dt.strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    table.columns = ["Risk", "Model Label", "Time", "Asset", "User", "Observable", "Source", "Threat", "Severity", "Action"]
    return table.head(250)


def render_mongo_warning(status: dict[str, object]) -> bool:
    if status.get("ok"):
        return False
    st.error(
        f"MongoDB is not reachable at {status.get('mongo_uri')} / {status.get('database')}: "
        f"{status.get('error') or 'unknown error'}"
    )
    return True


def render_workplace_mongo_page(global_frame: pd.DataFrame, mongo_context: dict[str, object]) -> None:
    status = mongo_context["status"]
    mongo_global = mongo_context["global_indicators"]
    pipeline = build_intelligence_pipeline(global_frame, mongo_context)
    workspace = pipeline["workspace_observables"]

    st.markdown(
        """
        <div class="page-hero">
            <div>
                <div class="eyebrow">Data Layer</div>
                <h2>Workplace Mongo + Global Intel</h2>
                <p>One view for MongoDB collections, normalized IOCs, and internal observables extracted from workplace logs.</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if render_mongo_warning(status):
        return

    collection_count = len(status.get("collections", []))
    render_metric_cards(
        [
            ("Mongo Collections", collection_count, f"{DEFAULT_MONGO_DB} at {DEFAULT_MONGO_URI}"),
            ("Mongo Global IOCs", len(mongo_global), "URLhaus, Feodo, MISP context normalized"),
            ("Dashboard Global IOCs", len(global_frame), "Existing SQLite/live-feed intelligence"),
            (
                "Workplace Observables",
                len(workspace),
                "URLs, domains, IPs, hashes from MongoDB logs",
            ),
            ("Correlation Candidates", len(pipeline["combined_global"]), "Unified global signal set"),
        ],
        columns_count=5,
    )

    st.markdown("<div style='height: 1rem'></div>", unsafe_allow_html=True)
    collections = pd.DataFrame(status.get("collections", []))
    if not collections.empty:
        render_dark_table(
            collections.rename(columns={"collection": "Collection", "documents": "Documents", "role": "Role"}),
            title="MongoDB Collection Map",
            subtitle="Collections marked global_intel are known threat datasets. Other collections are treated as workplace logs.",
            max_rows=12,
            height=380,
        )

    left, right = st.columns(2)
    with left:
        render_dark_table(
            format_mongo_global_table(mongo_global),
            title="Mongo Global Intelligence",
            subtitle="Normalized malicious URL/IP records plus lower-risk MISP warninglist context.",
            max_rows=12,
            height=430,
        )
    with right:
        seed_info = pipeline.get("mongo_seed", {})
        if seed_info.get("seeded"):
            st.info(
                f"No workplace log collections were found, so Drift seeded a MongoDB collection "
                f"`{seed_info.get('collection')}` with {seed_info.get('inserted_events')} demo events inside drift_db."
            )
        render_dark_table(
            format_workspace_table(workspace),
            title="Workplace Observable Stream",
            subtitle="Internal observables extracted from MongoDB log collections.",
            max_rows=12,
            height=430,
        )


def render_correlation_page(global_frame: pd.DataFrame, mongo_context: dict[str, object]) -> None:
    status = mongo_context["status"]
    pipeline = build_intelligence_pipeline(global_frame, mongo_context)
    workspace = pipeline["workspace_observables"]
    scored = pipeline["scored_correlations"]

    st.markdown(
        """
        <div class="page-hero">
            <div>
                <div class="eyebrow">Correlation Engine</div>
                <h2>Global Threat Intel vs Workplace Logs</h2>
                <p>Matches internal URLs, domains, IPs, and hashes against the unified global intelligence layer.</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if render_mongo_warning(status):
        return

    high_risk = len(scored[scored["risk_score"] >= 70]) if not scored.empty else 0
    affected_assets = scored["asset"].replace("", pd.NA).dropna().nunique() if not scored.empty else 0
    render_metric_cards(
        [
            ("Unified Global IOCs", len(pipeline["combined_global"]), "SQLite feeds + MongoDB datasets"),
            ("Workplace Observables", len(workspace), "Internal extracted evidence"),
            ("Matched Exposures", len(scored), "Global indicators seen in internal logs"),
            ("High Risk", high_risk, "AI score >= 70"),
            ("Affected Assets", affected_assets, "Unique assets from correlated logs"),
        ],
        columns_count=5,
    )

    st.markdown("<div style='height: 1rem'></div>", unsafe_allow_html=True)
    seed_info = pipeline.get("mongo_seed", {})
    if seed_info.get("seeded"):
        st.info(
            f"Workplace logs were auto-seeded into MongoDB collection `{seed_info.get('collection')}` "
            f"({seed_info.get('inserted_events')} events) to enable correlation + modeling."
        )
    if scored.empty:
        st.success("No current workplace observable matches the unified global threat intelligence set.")
        return

    left, right = st.columns([1.4, 1])
    with left:
        render_dark_table(
            format_correlation_table(scored),
            title="Correlated Exposure Queue",
            subtitle="Ranked by explainable AI risk score using severity, confidence, recency, source agreement, and IOC type.",
            max_rows=14,
            height=560,
        )
    with right:
        label_mix = scored["model_label"].value_counts().reset_index()
        label_mix.columns = ["Model Label", "Count"]
        render_dark_table(
            label_mix,
            title="Risk Label Mix",
            subtitle="Model output distribution for matched exposures.",
            max_rows=8,
            height=260,
        )
        st.markdown('<div style="height: 1rem"></div>', unsafe_allow_html=True)
        source_mix = scored["source"].value_counts().reset_index().head(8)
        source_mix.columns = ["Source", "Matches"]
        render_dark_table(
            source_mix,
            title="Source Evidence",
            subtitle="Threat sources contributing to workplace matches.",
            max_rows=8,
            height=260,
        )


def render_ai_modeling_page(global_frame: pd.DataFrame, mongo_context: dict[str, object]) -> None:
    status = mongo_context["status"]
    pipeline = build_intelligence_pipeline(global_frame, mongo_context)
    scored = pipeline["scored_correlations"]
    anomalies = pipeline["anomalies"]
    trends = pipeline["trends"]

    st.markdown(
        """
        <div class="page-hero">
            <div>
                <div class="eyebrow">AI Phase</div>
                <h2>Modeling, Risk Scoring, and Prediction</h2>
                <p>Explainable models for exposure scoring, workplace anomaly detection, and threat trend forecasting.</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if render_mongo_warning(status):
        return

    seed_info = pipeline.get("mongo_seed", {})
    if seed_info.get("seeded"):
        st.info(
            f"AI pages are using MongoDB workplace collection `{seed_info.get('collection')}` seeded with "
            f"{seed_info.get('inserted_events')} demo events (stored in drift_db)."
        )

    anomaly_count = int(anomalies["is_anomaly"].sum()) if not anomalies.empty and "is_anomaly" in anomalies else 0
    rising_count = len(trends[trends["trend_signal"] == "rising"]) if not trends.empty else 0
    critical_count = len(scored[scored["model_label"].isin(["Critical exposure", "High risk"])]) if not scored.empty else 0

    render_metric_cards(
        [
            ("Modeled Exposures", len(scored), "Correlation rows scored by risk model"),
            ("Critical / High", critical_count, "Exposures requiring SOC action"),
            ("Anomaly Windows", anomaly_count, "IsolationForest or statistical baseline"),
            ("Rising Threats", rising_count, "Forecasted growth categories"),
        ],
        columns_count=4,
    )

    st.markdown(
        f"""
        <div class="model-summary">
            <div class="model-summary-title">SOC AI Narrative</div>
            <p>{html.escape(pipeline["narrative"])}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    left, right = st.columns([1.35, 1])
    with left:
        render_dark_table(
            format_correlation_table(scored),
            title="Explainable Risk Model Output",
            subtitle="Each row includes a model label and recommended SOC action.",
            max_rows=10,
            height=430,
        )
    with right:
        model_cards = pd.DataFrame(
            [
                {
                    "Model": "Exposure Risk Scoring",
                    "Purpose": "Prioritize correlated internal/global IOC matches",
                    "Features": "severity, confidence, recency, IOC type, source count",
                },
                {
                    "Model": "Workplace Anomaly Detection",
                    "Purpose": "Find unusual observable intake windows",
                    "Features": "hourly event count, unique observables, collection",
                },
                {
                    "Model": "Predictive Trend Forecast",
                    "Purpose": "Estimate next-day growth by threat type",
                    "Features": "recent vs previous daily averages",
                },
            ]
        )
        render_dark_table(
            model_cards,
            title="AI/ML Model Inventory",
            subtitle="Hackathon-friendly modeling layer with explainable outputs.",
            max_rows=4,
            height=430,
        )

    lower_left, lower_right = st.columns(2)
    with lower_left:
        render_dark_table(
            anomalies.head(12),
            title="Anomaly Detection Output",
            subtitle="Hourly windows ranked by model anomaly score.",
            max_rows=12,
            height=430,
        )
    with lower_right:
        render_dark_table(
            trends.head(12),
            title="Predictive Threat Trends",
            subtitle="Threat categories ranked by recent growth and forecast.",
            max_rows=12,
            height=430,
        )


def inject_styles() -> None:
    st.markdown(
        f"""
        <style>
            header[data-testid="stHeader"] {{
                display: none !important;
                height: 0 !important;
            }}
            .stAppToolbar {{
                display: none !important;
            }}
            [data-testid="stToolbar"] {{
                display: none !important;
            }}
            [data-testid="stDecoration"] {{
                display: none !important;
            }}
            #MainMenu {{
                display: none !important;
            }}
            footer {{
                display: none !important;
            }}
            .stApp {{
                background:
                    radial-gradient(circle at top left, rgba(23, 192, 235, 0.16), transparent 24%),
                    radial-gradient(circle at 85% 15%, rgba(255, 45, 85, 0.18), transparent 20%),
                    linear-gradient(135deg, #050c14 0%, #08131d 42%, #0c1622 100%);
                color: {CYBER_COLORS["text"]};
            }}
            .block-container {{
                padding-top: 0.35rem;
                padding-bottom: 2rem;
                max-width: 100%;
            }}
            [data-testid="stSidebar"] {{
                display: none;
            }}
            [data-testid="stMetric"] {{
                background: transparent;
                border: none;
                padding: 0;
            }}
            h1, h2, h3, label, p, div {{
                color: {CYBER_COLORS["text"]};
            }}
            .hero-shell {{
                display: flex;
                justify-content: space-between;
                gap: 1.2rem;
                background:
                    linear-gradient(120deg, rgba(12, 22, 34, 0.94), rgba(16, 26, 42, 0.96)),
                    radial-gradient(circle at right, rgba(23, 192, 235, 0.18), transparent 30%);
                border: 1px solid rgba(255,255,255,0.08);
                border-radius: 24px;
                padding: 1.5rem 1.6rem;
                box-shadow: 0 18px 50px rgba(0,0,0,0.28);
                margin-bottom: 1.1rem;
            }}
            .hero-copy h1 {{
                margin: 0.15rem 0 0.5rem 0;
                font-size: 2.15rem;
                letter-spacing: -0.03em;
            }}
            .hero-copy p {{
                color: {CYBER_COLORS["muted"]};
                margin: 0;
                max-width: 850px;
            }}
            .eyebrow {{
                text-transform: uppercase;
                letter-spacing: 0.16em;
                font-size: 0.78rem;
                color: {CYBER_COLORS["accent_2"]};
            }}
            .hero-focus {{
                min-width: 300px;
                border-radius: 18px;
                padding: 1rem 1.1rem;
                background: linear-gradient(180deg, rgba(255, 45, 85, 0.18), rgba(10, 21, 35, 0.88));
                border: 1px solid rgba(255,255,255,0.08);
            }}
            .focus-label {{
                color: {CYBER_COLORS["muted"]};
                font-size: 0.8rem;
                text-transform: uppercase;
                letter-spacing: 0.12em;
            }}
            .focus-value {{
                font-size: 1.15rem;
                font-weight: 700;
                margin-top: 0.5rem;
                word-break: break-word;
            }}
            .focus-meta {{
                margin-top: 0.7rem;
                color: {CYBER_COLORS["muted"]};
                font-size: 0.9rem;
            }}
            .metric-card {{
                background: linear-gradient(180deg, rgba(16, 27, 40, 0.96), rgba(10, 18, 30, 0.98));
                border: 1px solid rgba(255,255,255,0.08);
                border-radius: 18px;
                padding: 0.95rem 1rem;
                min-height: 132px;
                box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
            }}
            .metric-title {{
                color: {CYBER_COLORS["muted"]};
                font-size: 0.85rem;
                text-transform: uppercase;
                letter-spacing: 0.08em;
            }}
            .metric-value {{
                font-size: 2rem;
                line-height: 1.1;
                font-weight: 800;
                margin-top: 0.65rem;
                color: {CYBER_COLORS["text"]};
            }}
            .metric-subtitle {{
                margin-top: 0.4rem;
                color: {CYBER_COLORS["muted"]};
                font-size: 0.84rem;
            }}
            .panel-title {{
                font-size: 1.08rem;
                font-weight: 700;
                margin-bottom: 0.65rem;
                margin-top: 0.15rem;
                letter-spacing: 0.01em;
            }}
            .page-hero {{
                background: linear-gradient(120deg, rgba(12, 22, 34, 0.94), rgba(11, 20, 31, 0.96));
                border: 1px solid rgba(255,255,255,0.08);
                border-radius: 20px;
                padding: 1.2rem 1.3rem;
                margin-bottom: 1rem;
            }}
            .page-hero h2 {{
                margin: 0.2rem 0 0.35rem 0;
                font-size: 1.8rem;
            }}
            .page-hero p {{
                margin: 0;
                color: {CYBER_COLORS["muted"]};
            }}
            .report-nav-label {{
                color: {CYBER_COLORS["muted"]};
                font-size: 0.82rem;
                text-transform: uppercase;
                letter-spacing: 0.14em;
                margin-bottom: 0.35rem;
            }}
            .status-chip {{
                background: rgba(14, 26, 39, 0.92);
                border: 1px solid rgba(255,255,255,0.07);
                border-radius: 14px;
                padding: 0.8rem 0.9rem;
            }}
            .status-chip span {{
                display: block;
                color: {CYBER_COLORS["muted"]};
                font-size: 0.8rem;
                text-transform: uppercase;
                letter-spacing: 0.08em;
            }}
            .status-chip strong {{
                display: block;
                margin-top: 0.35rem;
                font-size: 1rem;
                color: {CYBER_COLORS["text"]};
            }}
            .model-summary {{
                margin: 1rem 0;
                background: linear-gradient(120deg, rgba(20, 241, 149, 0.12), rgba(23, 192, 235, 0.08));
                border: 1px solid rgba(20, 241, 149, 0.18);
                border-radius: 18px;
                padding: 1rem 1.1rem;
                box-shadow: 0 18px 44px rgba(0,0,0,0.22);
            }}
            .model-summary-title {{
                color: {CYBER_COLORS["accent_2"]};
                font-weight: 800;
                text-transform: uppercase;
                letter-spacing: 0.1em;
                font-size: 0.78rem;
                margin-bottom: 0.45rem;
            }}
            .model-summary p {{
                margin: 0;
                color: {CYBER_COLORS["text"]};
                line-height: 1.55;
            }}
            [data-baseweb="input"] > div {{
                background: rgba(255,255,255,0.98);
                border-radius: 16px;
            }}
            [data-testid="stDataFrame"] {{
                border: 1px solid rgba(255,255,255,0.06);
                border-radius: 18px;
                overflow: hidden;
            }}
            [data-testid="stDataFrame"] *:focus {{
                outline: none !important;
                box-shadow: none !important;
            }}
            .stButton > button {{
                border-radius: 14px;
                border: 1px solid rgba(255,255,255,0.08);
                background: linear-gradient(90deg, #0f2d45, #133a59);
                color: white;
                font-weight: 700;
                min-height: 44px;
            }}
            .stSlider [data-baseweb="slider"] div[role="slider"] {{
                background-color: {CYBER_COLORS["critical"]};
            }}
            [data-baseweb="select"] > div, [data-baseweb="popover"] {{
                background: rgba(10, 19, 31, 0.95);
                border-radius: 14px;
            }}
            [data-baseweb="tag"] {{
                background: rgba(23, 192, 235, 0.18) !important;
                border-radius: 999px !important;
            }}
            [data-testid="stRadio"] > div {{
                background: rgba(11, 21, 33, 0.82);
                border: 1px solid rgba(255,255,255,0.07);
                border-radius: 16px;
                padding: 0.4rem;
                gap: 0.45rem;
                margin-bottom: 1rem;
            }}
            [data-testid="stRadio"] label {{
                background: rgba(255,255,255,0.02);
                border: 1px solid rgba(255,255,255,0.05);
                border-radius: 12px;
                padding: 0.55rem 0.9rem;
            }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def merge_sqlite_and_mongo_intel(sqlite_frame: pd.DataFrame, mongo_context: dict[str, object]) -> pd.DataFrame:
    mongo_global = mongo_context.get("global_indicators")
    if not isinstance(mongo_global, pd.DataFrame):
        mongo_global = pd.DataFrame()

    combined = pd.concat([normalize_sqlite_intel(sqlite_frame), mongo_global], ignore_index=True)
    if combined.empty:
        return combined

    combined = combined.drop_duplicates(subset=["indicator_type", "indicator_value", "source"])

    for column in ["first_seen", "last_seen"]:
        if column in combined.columns:
            combined[column] = pd.to_datetime(combined[column], format="mixed", utc=True, errors="coerce")

    # Charts and trend views expect a timestamp column.
    if "created_at" not in combined.columns:
        if "first_seen" in combined.columns:
            combined["created_at"] = combined["first_seen"]
        elif "last_seen" in combined.columns:
            combined["created_at"] = combined["last_seen"]
        else:
            combined["created_at"] = pd.Timestamp.utcnow()
    combined["created_at"] = pd.to_datetime(combined["created_at"], format="mixed", utc=True, errors="coerce")

    # Some views aggregate counts by id; ensure it's always present.
    if "id" not in combined.columns:
        combined = combined.reset_index(drop=True)
        combined["id"] = combined.index.astype(int)

    combined["severity"] = combined["severity"].astype(str).str.lower()
    combined["threat_type"] = combined["threat_type"].astype(str).str.lower()
    combined["indicator_type"] = combined["indicator_type"].astype(str).str.lower()
    combined["severity_score"] = combined["severity"].map(SEVERITY_SCORE).fillna(1)
    combined["confidence"] = pd.to_numeric(combined["confidence"], errors="coerce").fillna(0).astype(int)
    combined["country"] = combined.apply(derive_country, axis=1)
    return combined


def main() -> None:
    inject_styles()
    sqlite_frame = load_data()
    mongo_context = load_mongo_dashboard_data()
    frame = merge_sqlite_and_mongo_intel(sqlite_frame, mongo_context)

    if frame.empty:
        st.error("No threat intelligence data is available in SQLite or Mongo.")
        return

    refresh_summary, filtered_frame = render_control_ribbon(frame)
    render_soc_copilot(filtered_frame, mongo_context)
    page = render_report_nav()

    if page == "Overview":
        render_overview_page(filtered_frame, refresh_summary)
    elif page == "IOC Explorer":
        render_ioc_explorer_page(filtered_frame)
    elif page == "Geo Intel":
        render_geo_page(filtered_frame)
    elif page == "Feed Ops":
        render_feed_ops_page(filtered_frame, refresh_summary)
    else:
        if page == "Workplace Mongo":
            render_workplace_mongo_page(frame, mongo_context)
        elif page == "Correlation":
            render_correlation_page(frame, mongo_context)
        else:
            render_ai_modeling_page(frame, mongo_context)


if __name__ == "__main__":
    main()
