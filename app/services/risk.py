from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

SEVERITY_IMPACT = {"CRITICAL": 10.0, "HIGH": 4.0, "MEDIUM": 1.5, "LOW": 1.0}
POSTURE_LABELS = ((85, "GOOD"), (70, "MODERATE"), (50, "HIGH RISK"), (0, "CRITICAL RISK"))


def posture_score(findings: list[dict[str, Any]]) -> int:
    # Bounded deterministic posture metric. It is not CVSS and is meant for portfolio-level comparison.
    penalty = sum(SEVERITY_IMPACT.get(f["severity"], 0) for f in findings)
    return max(0, min(100, round(100 - penalty)))


def label(score: int) -> str:
    for threshold, text in POSTURE_LABELS:
        if score >= threshold:
            return text
    return "CRITICAL RISK"


def summarize(sessions: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, Any]:
    sev = Counter(f["severity"] for f in findings)
    protocols = Counter(s["protocol"] for s in sessions)
    categories = Counter(f["category"] for f in findings)
    secure_sessions = sum(1 for s in sessions if s.get("tls_version") not in {"PLAINTEXT", "UNKNOWN", "NONE"})
    return {
        "sessions": len(sessions),
        "secure_sessions": secure_sessions,
        "findings": len(findings),
        "critical": sev.get("CRITICAL", 0),
        "high": sev.get("HIGH", 0),
        "medium": sev.get("MEDIUM", 0),
        "low": sev.get("LOW", 0),
        "protocols": dict(protocols),
        "categories": dict(categories),
    }


def control_effects(findings: list[dict[str, Any]]) -> dict[str, float]:
    effects = defaultdict(float)
    for f in findings:
        effects[f["control"]] += SEVERITY_IMPACT.get(f["severity"], 0)
    return dict(effects)


def what_if(findings: list[dict[str, Any]], actions: list[str]) -> dict[str, Any]:
    actions = sorted(set(a.lower().strip() for a in actions))
    current = posture_score(findings)
    remaining = [f for f in findings if f.get("control") not in actions]
    projected = posture_score(remaining)
    effects = control_effects(findings)
    return {
        "current_score": current,
        "projected_score": projected,
        "delta": projected - current,
        "actions": actions,
        "control_impact": {a: round(effects.get(a, 0), 1) for a in actions},
        "remaining_findings": len(remaining),
        "explanation": "Projection re-runs the same deterministic posture model after suppressing findings addressed by the selected remediation controls. It does not modify a live mail server.",
    }
