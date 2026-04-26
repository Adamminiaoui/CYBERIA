from __future__ import annotations

from datetime import UTC, datetime

import hashlib
import pandas as pd

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
except Exception:  # pragma: no cover - dashboard falls back to statistical scoring
    IsolationForest = None
    RandomForestClassifier = None
    RandomForestRegressor = None


SEVERITY_BASE = {"low": 18, "medium": 45, "high": 72, "critical": 92}
IOC_BONUS = {"url": 8, "domain": 5, "ip": 7, "hash": 6}


def _empty_scored() -> pd.DataFrame:
    return pd.DataFrame(
        columns=[
            "event_time",
            "event_collection",
            "user",
            "asset",
            "observable_type",
            "observable_value",
            "source",
            "threat_type",
            "severity",
            "confidence",
            "risk_score",
            "model_label",
            "model_reason",
            "recommended_action",
        ]
    )


def _safe_str(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _age_bonus(event_time) -> int:
    if pd.isna(event_time):
        return 0
    now = datetime.now(UTC)
    age_hours = max((now - event_time.to_pydatetime().astimezone(UTC)).total_seconds() / 3600, 0)
    if age_hours <= 24:
        return 10
    if age_hours <= 168:
        return 5
    return 0


def _label(score: int, threat_type: str) -> str:
    if threat_type == "warninglist_context":
        return "Context"
    if score >= 85:
        return "Critical exposure"
    if score >= 70:
        return "High risk"
    if score >= 45:
        return "Investigate"
    return "Watchlist"


def _action(label: str, threat_type: str) -> str:
    if label == "Context":
        return "Use as enrichment context; do not treat as malicious without another signal."
    if label == "Critical exposure":
        return "Escalate now: isolate affected asset, block indicator, preserve logs, and reset exposed credentials."
    if label == "High risk":
        return "Block the indicator, hunt for related events, and validate the affected user or endpoint."
    if label == "Investigate":
        return "Open a triage case and compare with proxy, DNS, endpoint, and authentication logs."
    return "Monitor and enrich with additional sources before escalation."


def _severity_score(severity: str) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(_safe_str(severity).lower(), 1)


def _match_quality_score(match_quality: str) -> int:
    value = _safe_str(match_quality).lower()
    if value == "exact":
        return 2
    if value in {"url_domain", "domain"}:
        return 1
    return 0


def _ioc_type_score(obs_type: str) -> int:
    return {"url": 4, "ip": 3, "domain": 2, "hash": 3}.get(_safe_str(obs_type).lower(), 1)


def _age_hours(event_time) -> float:
    if pd.isna(event_time):
        return 999.0
    now = datetime.now(UTC)
    return max((now - event_time.to_pydatetime().astimezone(UTC)).total_seconds() / 3600, 0.0)


def _heuristic_risk_score(row: pd.Series) -> int:
    threat_type = _safe_str(row.get("threat_norm"))
    severity = _safe_str(row.get("severity_norm"))
    confidence = int(row.get("confidence") or 0)
    base = SEVERITY_BASE.get(severity, 30)
    ioc_bonus = IOC_BONUS.get(_safe_str(row.get("observable_type")).lower(), 0)
    source_bonus = min(max(int(row.get("source_count") or 1) - 1, 0) * 6, 18)
    recent_bonus = _age_bonus(row.get("event_time"))

    score = round((base * 0.52) + (confidence * 0.34) + ioc_bonus + source_bonus + recent_bonus)
    if threat_type == "warninglist_context":
        score = min(score, 35)
    return max(0, min(100, score))


def _stable_jitter(*parts: str, span: int = 23) -> int:
    """Small deterministic offset to avoid identical-looking scores."""
    raw = "|".join([_safe_str(p) for p in parts if _safe_str(p)])
    if not raw:
        return 0
    digest = hashlib.md5(raw.encode("utf-8")).hexdigest()
    value = int(digest[:8], 16)
    half = span // 2
    return (value % span) - half  # e.g. span=7 -> [-3..+3]


def _rf_features(scored: pd.DataFrame) -> pd.DataFrame:
    frame = scored.copy()
    frame["event_time"] = pd.to_datetime(frame["event_time"], format="mixed", utc=True, errors="coerce")
    return pd.DataFrame(
        {
            "severity_score": frame["severity_norm"].astype(str).map(_severity_score).astype(int),
            "confidence": pd.to_numeric(frame["confidence"], errors="coerce").fillna(0).astype(int),
            "source_count": pd.to_numeric(frame["source_count"], errors="coerce").fillna(1).astype(int),
            "ioc_type_score": frame["observable_type"].astype(str).map(_ioc_type_score).fillna(1).astype(int),
            "match_quality_score": frame["match_quality"].astype(str).map(_match_quality_score).fillna(0).astype(int),
            "age_hours": frame["event_time"].apply(_age_hours).astype(float),
        }
    )


def score_correlations(correlations: pd.DataFrame) -> pd.DataFrame:
    if correlations.empty:
        return _empty_scored()

    scored = correlations.copy()
    scored["severity_norm"] = scored["severity"].astype(str).str.lower()
    scored["threat_norm"] = scored["threat_type"].astype(str).str.lower()
    scored["source_count"] = scored.groupby("observable_value")["source"].transform("nunique")

    risk_scores: list[int] = []
    reasons: list[str] = []
    labels: list[str] = []
    actions: list[str] = []

    # Random Forest scoring (self-trained using heuristic labels for PoC).
    # If sklearn isn't available or dataset too small, fall back to heuristics.
    use_rf = RandomForestClassifier is not None and len(scored) >= 25

    if use_rf:
        features = _rf_features(scored)
        heuristic_scores = scored.apply(_heuristic_risk_score, axis=1)
        y = pd.cut(
            heuristic_scores,
            bins=[-1, 44, 69, 100],
            labels=["watch", "investigate", "high"],
        ).astype(str)

        model = RandomForestClassifier(
            n_estimators=260,
            random_state=7,
            class_weight="balanced_subsample",
            min_samples_leaf=2,
            n_jobs=-1,
        )
        model.fit(features, y)
        proba = model.predict_proba(features)
        class_index = {cls: idx for idx, cls in enumerate(model.classes_)}

        # Convert to a 0..100 risk score emphasizing high/investigate probabilities.
        p_high = proba[:, class_index.get("high", 0)] if "high" in class_index else 0.0
        p_inv = proba[:, class_index.get("investigate", 0)] if "investigate" in class_index else 0.0
        rf_score = (p_high * 92.0) + (p_inv * 62.0)

        for idx, row in scored.iterrows():
            threat_type = _safe_str(row.get("threat_norm"))
            severity = _safe_str(row.get("severity_norm"))
            confidence = int(row.get("confidence") or 0)
            score = int(max(0, min(100, round(float(rf_score[idx])))))
            jitter = _stable_jitter(
                _safe_str(row.get("observable_value")),
                _safe_str(row.get("source")),
                _safe_str(row.get("event_collection")),
            )
            score = int(
                max(
                    0,
                    min(
                        100,
                        score
                        + jitter,
                    ),
                )
            )
            # Avoid score saturation (too many 100s) while keeping ordering stable.
            if score >= 98:
                score = 93 + (abs(jitter) % 7)  # 93..99 deterministic spread
            if threat_type == "warninglist_context":
                score = min(score, 35)
            label = _label(score, threat_type)

            reasons.append(
                f"RF model: {severity or 'unknown'} severity, {confidence}/100 confidence, "
                f"{int(row.get('source_count') or 1)} source(s), {row.get('match_quality')} match."
            )
            risk_scores.append(score)
            labels.append(label)
            actions.append(_action(label, threat_type))
    else:
        for _, row in scored.iterrows():
            threat_type = _safe_str(row.get("threat_norm"))
            severity = _safe_str(row.get("severity_norm"))
            confidence = int(row.get("confidence") or 0)
            score = _heuristic_risk_score(row)
            jitter = _stable_jitter(
                _safe_str(row.get("observable_value")),
                _safe_str(row.get("source")),
                _safe_str(row.get("event_collection")),
            )
            score = int(
                max(
                    0,
                    min(
                        100,
                        score
                        + jitter,
                    ),
                )
            )
            if score >= 98:
                score = 93 + (abs(jitter) % 7)
            label = _label(score, threat_type)
            reasons.append(
                f"Heuristic: {severity or 'unknown'} severity, {confidence}/100 confidence, "
                f"{int(row.get('source_count') or 1)} source(s), {row.get('match_quality')} match."
            )
            risk_scores.append(score)
            labels.append(label)
            actions.append(_action(label, threat_type))

    scored["risk_score"] = risk_scores
    scored["model_label"] = labels
    scored["model_reason"] = reasons
    scored["recommended_action"] = actions

    return scored.sort_values(["risk_score", "confidence"], ascending=[False, False]).reset_index(drop=True)


def detect_workplace_anomalies(workspace_observables: pd.DataFrame) -> pd.DataFrame:
    if workspace_observables.empty or "event_time" not in workspace_observables:
        return pd.DataFrame(columns=["hour", "event_collection", "event_count", "unique_observables", "model", "is_anomaly"])

    frame = workspace_observables.copy()
    frame["event_time"] = pd.to_datetime(frame["event_time"], format="mixed", utc=True, errors="coerce")
    frame = frame.dropna(subset=["event_time"])
    if frame.empty:
        return pd.DataFrame(columns=["hour", "event_collection", "event_count", "unique_observables", "model", "is_anomaly"])

    hourly = (
        frame.assign(hour=frame["event_time"].dt.floor("h"))
        .groupby(["hour", "event_collection"], as_index=False)
        .agg(event_count=("observable_value", "count"), unique_observables=("observable_value", "nunique"))
    )

    # Use RF regression when possible to model expected volume, otherwise fall back.
    if len(hourly) >= 16 and RandomForestRegressor is not None:
        hourly = hourly.sort_values("hour").reset_index(drop=True)
        hourly["hour_of_day"] = pd.to_datetime(hourly["hour"], utc=True).dt.hour.astype(int)
        hourly["day_of_week"] = pd.to_datetime(hourly["hour"], utc=True).dt.dayofweek.astype(int)
        X = hourly[["hour_of_day", "day_of_week", "unique_observables"]].astype(float)
        y = hourly["event_count"].astype(float)
        model = RandomForestRegressor(
            n_estimators=260,
            random_state=7,
            min_samples_leaf=2,
            n_jobs=-1,
        )
        model.fit(X, y)
        pred = model.predict(X)
        residual = y - pred
        sigma = float(residual.std(ddof=0) or 0.0)
        threshold = max(3.0, 2.25 * sigma)
        hourly["expected_count"] = pred.round(2)
        hourly["anomaly_score"] = (residual / (sigma + 1e-6)).round(3)
        hourly["is_anomaly"] = residual >= threshold
        hourly["model"] = "RandomForestRegressor"
    elif len(hourly) >= 8 and IsolationForest is not None:
        features = hourly[["event_count", "unique_observables"]].astype(float)
        model = IsolationForest(random_state=7, contamination="auto")
        hourly["is_anomaly"] = model.fit_predict(features) == -1
        hourly["anomaly_score"] = -model.score_samples(features)
        hourly["model"] = "IsolationForest"
    else:
        threshold = hourly["event_count"].mean() + (2 * hourly["event_count"].std(ddof=0))
        if pd.isna(threshold) or threshold == 0:
            threshold = hourly["event_count"].max()
        hourly["is_anomaly"] = hourly["event_count"] >= threshold
        hourly["anomaly_score"] = hourly["event_count"]
        hourly["model"] = "statistical_baseline"

    return hourly.sort_values(["is_anomaly", "anomaly_score"], ascending=[False, False]).reset_index(drop=True)


def forecast_threat_trends(global_indicators: pd.DataFrame) -> pd.DataFrame:
    if global_indicators.empty:
        return pd.DataFrame(columns=["threat_type", "recent_daily_avg", "previous_daily_avg", "trend_signal", "forecast_next_day"])

    frame = global_indicators.copy()
    time_col = "last_seen" if "last_seen" in frame else "created_at"
    frame[time_col] = pd.to_datetime(frame[time_col], format="mixed", utc=True, errors="coerce")
    frame = frame.dropna(subset=[time_col])
    if frame.empty:
        return pd.DataFrame(columns=["threat_type", "recent_daily_avg", "previous_daily_avg", "trend_signal", "forecast_next_day"])

    frame["day"] = frame[time_col].dt.date
    daily = frame.groupby(["threat_type", "day"], as_index=False).agg(count=("indicator_value", "count"))
    rows: list[dict] = []

    for threat_type, group in daily.groupby("threat_type"):
        ordered = group.sort_values("day")
        recent = ordered.tail(3)["count"]
        previous = ordered.iloc[max(len(ordered) - 6, 0) : max(len(ordered) - 3, 0)]["count"]
        recent_avg = float(recent.mean()) if not recent.empty else 0.0
        previous_avg = float(previous.mean()) if not previous.empty else recent_avg

        forecast = recent_avg
        model_used = "moving_avg"
        if len(ordered) >= 10 and RandomForestRegressor is not None:
            # RF time-series-ish: day index -> count
            ordered = ordered.reset_index(drop=True)
            ordered["t"] = ordered.index.astype(int)
            X = ordered[["t"]].astype(float)
            y = ordered["count"].astype(float)
            reg = RandomForestRegressor(
                n_estimators=260,
                random_state=7,
                min_samples_leaf=2,
                n_jobs=-1,
            )
            reg.fit(X, y)
            forecast = float(reg.predict(pd.DataFrame({"t": [float(len(ordered))]}))[0])
            model_used = "RandomForestRegressor"

        delta = forecast - recent_avg
        if delta > max(2, previous_avg * 0.25):
            signal = "rising"
        elif delta < -max(2, previous_avg * 0.25):
            signal = "falling"
        else:
            signal = "stable"
        rows.append(
            {
                "threat_type": threat_type,
                "recent_daily_avg": round(recent_avg, 2),
                "previous_daily_avg": round(previous_avg, 2),
                "trend_signal": signal,
                "forecast_next_day": max(0, round(forecast)),
                "forecast_model": model_used,
            }
        )

    return pd.DataFrame(rows).sort_values(["trend_signal", "forecast_next_day"], ascending=[False, False]).reset_index(drop=True)


def build_soc_narrative(
    scored_correlations: pd.DataFrame,
    anomalies: pd.DataFrame,
    trends: pd.DataFrame,
) -> str:
    if scored_correlations.empty:
        exposure_line = "No internal exposure has been correlated yet because no workplace IOC match was found."
    else:
        top = scored_correlations.iloc[0]
        exposure_line = (
            f"Highest exposure is {top['observable_value']} on asset {top.get('asset') or 'unknown'} "
            f"with a {int(top['risk_score'])}/100 risk score from {top.get('source')}."
        )

    anomaly_count = int(anomalies["is_anomaly"].sum()) if not anomalies.empty and "is_anomaly" in anomalies else 0
    anomaly_line = (
        f"Workplace behavior model found {anomaly_count} anomalous intake window(s)."
        if anomaly_count
        else "Workplace behavior model did not find a strong anomaly window in the current sample."
    )

    if trends.empty:
        trend_line = "Predictive trend model needs more time-series threat intelligence to forecast growth."
    else:
        rising = trends[trends["trend_signal"] == "rising"]
        if rising.empty:
            leader = trends.iloc[0]
            trend_line = f"Threat trend model sees {leader['threat_type']} as the largest current category, but trend is {leader['trend_signal']}."
        else:
            leader = rising.iloc[0]
            trend_line = f"Predictive trend model flags {leader['threat_type']} as rising, forecast around {leader['forecast_next_day']} indicators next day."

    return " ".join([exposure_line, anomaly_line, trend_line])
