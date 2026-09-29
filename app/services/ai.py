from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
KB_DIR = ROOT / "data" / "knowledge"


def load_kb() -> list[dict[str, str]]:
    items = []
    if not KB_DIR.exists():
        return items
    for path in sorted(KB_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for section in text.split("\n## "):
            if section.strip():
                title = section.splitlines()[0].lstrip("# ")[:120]
                body = "\n".join(section.splitlines()[1:]).strip()
                items.append({"title": title, "body": body, "source": path.name})
    return items


def retrieve(question: str, limit: int = 3) -> list[dict[str, str]]:
    terms = [x for x in question.lower().replace("?", " ").split() if len(x) > 2]
    scored = []
    for item in load_kb():
        hay = f"{item['title']} {item['body']}".lower()
        score = sum(hay.count(t) for t in terms)
        if score:
            scored.append((score, item))
    return [x[1] for x in sorted(scored, key=lambda z: z[0], reverse=True)[:limit]]


def _heuristic_answer(question: str, result: dict[str, Any], session: dict[str, Any] | None, finding: dict[str, Any] | None) -> dict[str, Any]:
    q = question.lower().strip()
    findings = result.get("findings", [])
    scope = findings
    if session:
        scope = [f for f in findings if f["session_id"] == session["session_id"]]
    if finding:
        scope = [finding]

    if "why" in q and ("risk" in q or "danger" in q):
        drivers = scope[:4] if scope else findings[:4]
        details = "; ".join(f"{f['finding_id']}: {f['title']} ({f['severity']})" for f in drivers)
        answer = f"The observed posture is {result['posture']} at {result['score']}/100. The strongest drivers in the selected context are {details}. These are evidence-backed observations from the captured sessions, not a prediction of compromise."
    elif any(w in q for w in ("fix", "remediate", "remediation", "recommend")):
        recs = []
        for f in scope[:5]:
            recs.append(f"{f['title']}: {f['recommendation']}")
        answer = "Recommended actions, ordered by the observed findings: " + " | ".join(recs or ["Run a scan and inspect the highest-severity findings first."])
    elif "certificate" in q or "cert" in q:
        certs = [f for f in findings if f["category"] == "Certificate"]
        answer = "Certificate-related observations: " + "; ".join(f"{f['session_id']}: {f['title']} ({f['observed']})" for f in certs[:6])
    elif "tls" in q:
        versions = sorted({s.get("tls_version") for s in result.get("sessions", [])})
        answer = f"Observed TLS state includes: {', '.join(str(v) for v in versions)}. The rule engine flags TLS 1.0/1.1 as deprecated and prefers TLS 1.2+ with TLS 1.3 where supported."
    else:
        answer = "I can explain the selected finding, summarize the risk drivers, review certificate evidence, or generate remediation guidance. Try: 'Why is this risky?', 'How do I fix it?', or 'Show certificate issues'."

    refs = [f["finding_id"] for f in scope[:5]]
    knowledge = [{"title": x["title"], "source": x["source"]} for x in retrieve(question)]
    return {"answer": answer, "evidence": refs, "knowledge": knowledge, "provider": "local-evidence-copilot"}


def answer(question: str, result: dict[str, Any], session: dict[str, Any] | None = None, finding: dict[str, Any] | None = None) -> dict[str, Any]:
    # Optional external LLM path. Disabled by default for deterministic, offline demo behavior.
    provider = os.getenv("SMS_AI_PROVIDER", "local").lower()
    if provider == "gemini" and os.getenv("GEMINI_API_KEY"):
        try:
            from google import genai
            client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
            prompt = {
                "question": question,
                "scan_summary": result.get("summary"),
                "selected_session": session,
                "selected_finding": finding,
                "evidence": result.get("findings", []),
            }
            response = client.models.generate_content(
                model=os.getenv("SMS_GEMINI_MODEL", "gemini-2.5-flash"),
                contents=("You are a cybersecurity assessment copilot. Do not claim compromise. Explain observations from the supplied evidence. Use standards listed in findings. Return concise, evidence-grounded guidance.\n" + json.dumps(prompt, default=str))
            )
            return {"answer": response.text, "evidence": [f["finding_id"] for f in (result.get("findings", [])[:5])], "knowledge": [], "provider": "gemini"}
        except Exception as exc:
            fallback = _heuristic_answer(question, result, session, finding)
            fallback["provider"] = f"local-fallback ({type(exc).__name__})"
            return fallback
    return _heuristic_answer(question, result, session, finding)
