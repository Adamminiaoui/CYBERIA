from __future__ import annotations

import html
import sys
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
    top_cols = st.columns([1.1, 1.1, 1.1, 0.95, 1.15, 1.15, 1.15, 0.9])

    auto_refresh_seconds = top_cols[0].select_slider(
        "Dashboard Refresh",
        options=[15, 30, 45, 60, 90, 120, 180, 240, 300],
        value=60,
    )
    refresh_interval_minutes = top_cols[1].select_slider(
        "Feed Poll Interval",
        options=[5, 10, 15, 20, 30, 45, 60],
        value=15,
    )
    per_feed_limit = top_cols[2].select_slider(
        "Records Per Feed",
        options=[25, 50, 75, 100, 150, 200, 250],
        value=100,
    )

    st_autorefresh(interval=auto_refresh_seconds * 1000, key="dashboard_refresh")
    refresh_summary = maybe_refresh_live_feeds(
        refresh_interval_minutes=refresh_interval_minutes,
        per_feed_limit=per_feed_limit,
    )

    threat_types = sorted(frame["threat_type"].dropna().unique().tolist())
    severities = sorted(frame["severity"].dropna().unique().tolist())
    sources = sorted(frame["source"].dropna().unique().tolist())

    selected_threat_types = top_cols[3].multiselect(
        "Threat Type",
        options=threat_types,
        default=threat_types,
    )
    selected_severities = top_cols[4].multiselect(
        "Severity",
        options=severities,
        default=severities,
    )
    selected_sources = top_cols[5].multiselect(
        "Source",
        options=sources,
        default=sources,
    )
    selected_indicator_types = top_cols[6].multiselect(
        "IOC Type",
        options=sorted(frame["indicator_type"].dropna().unique().tolist()),
        default=sorted(frame["indicator_type"].dropna().unique().tolist()),
    )

    if top_cols[7].button("Refresh Now", use_container_width=True):
        refresh_summary = refresh_live_feeds(per_feed_limit=per_feed_limit)
        st.success(
            f"Refresh finished: {refresh_summary['inserted']} inserted, {refresh_summary['updated']} updated."
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
        options=["Overview", "IOC Explorer", "Geo Intel", "Feed Ops"],
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
    geo_frame["lat"] = geo_frame["country"].map(lambda name: COUNTRY_COORDS.get(name, COUNTRY_COORDS["Global"])[0])
    geo_frame["lon"] = geo_frame["country"].map(lambda name: COUNTRY_COORDS.get(name, COUNTRY_COORDS["Global"])[1])

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
                        size=geo_frame["threat_count"].clip(lower=1) * 3,
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
    geo_summary = (
        frame.groupby(["country", "severity"], as_index=False)
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
        region_counts = frame["country"].value_counts().reset_index().head(10)
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
    render_charts(frame)

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


def main() -> None:
    inject_styles()
    frame = load_data()

    if frame.empty:
        st.error("No threat intelligence data is available.")
        return

    refresh_summary, filtered_frame = render_control_ribbon(frame)
    page = render_report_nav()

    if page == "Overview":
        render_overview_page(filtered_frame, refresh_summary)
    elif page == "IOC Explorer":
        render_ioc_explorer_page(filtered_frame)
    elif page == "Geo Intel":
        render_geo_page(filtered_frame)
    else:
        render_feed_ops_page(filtered_frame, refresh_summary)


if __name__ == "__main__":
    main()
