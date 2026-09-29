from __future__ import annotations

from typing import Any


def anomaly_scores(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
    except Exception:
        return [{"session_id": s["session_id"], "protocol": s["protocol"], "anomaly_score": 0.5, "method": "fallback"} for s in sessions]

    rows = []
    for s in sessions:
        tls_map = {"PLAINTEXT": 0, "TLS 1.0": 1, "TLS 1.1": 2, "TLS 1.2": 3, "TLS 1.3": 4}
        cipher = str(s.get("cipher_suite", "")).upper()
        features = [
            tls_map.get(str(s.get("tls_version")), 0),
            1 if any(x in cipher for x in ("RC4", "3DES", "DES-CBC")) else 0,
            1 if s.get("forward_secrecy") else 0,
            float(s.get("cert_days_left") or 0),
            float(s.get("packet_count") or 0),
            float(s.get("duration_ms") or 0),
            1 if str(s.get("certificate", "")).lower() == "expired" else 0,
            1 if s.get("hostname_match", True) is False else 0,
        ]
        rows.append(features)
    X = np.asarray(rows, dtype=float)
    if len(X) < 3:
        return [{"session_id": s["session_id"], "protocol": s["protocol"], "anomaly_score": 0.5, "method": "insufficient-samples"} for s in sessions]
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    model.fit(X)
    raw = model.decision_function(X)
    # Normalize relative to observed range for a UI-friendly 0..1 anomaly score.
    lo, hi = float(raw.min()), float(raw.max())
    out: list[dict[str, Any]] = []
    for s, r in zip(sessions, raw):
        normal = (float(r) - lo) / (hi - lo) if hi > lo else 0.5
        out.append({
            "session_id": s["session_id"],
            "protocol": s["protocol"],
            "anomaly_score": round(1 - normal, 3),
            "method": "IsolationForest",
        })
    return sorted(out, key=lambda x: x["anomaly_score"], reverse=True)
