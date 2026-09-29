from __future__ import annotations

import json
import sqlite3
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel, Field

from .services.ai import answer as copilot_answer
from .services.audit import make_chain, verify_chain
from .services.ml import anomaly_scores
from .services.pcap import analyze_pcap
from .services.report import generate_pdf
from .services.risk import label, posture_score, summarize, what_if
from .services.rules import analyze_sessions

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
DATA = ROOT / "data"
STORAGE = ROOT / "storage"
REPORTS = ROOT / "reports"
UPLOADS = STORAGE / "uploads"
for directory in (DATA, STORAGE, REPORTS, UPLOADS):
    directory.mkdir(parents=True, exist_ok=True)
DB = STORAGE / "securemailscope.db"

app = FastAPI(title="SecureMailScope", version="1.0.0", description="SIH26159 passive email cryptographic posture assessment")


def db() -> sqlite3.Connection:
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with db() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                mode TEXT NOT NULL,
                input_file TEXT,
                result_json TEXT NOT NULL,
                audit_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS app_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event TEXT NOT NULL,
                scan_id TEXT,
                detail TEXT
            );
            """
        )


init_db()

CURRENT_SCAN_ID: str | None = None


class WhatIfRequest(BaseModel):
    scan_id: str
    actions: list[str] = Field(default_factory=list)


class CopilotRequest(BaseModel):
    scan_id: str
    question: str = Field(min_length=1, max_length=2000)
    session_id: str | None = None
    finding_id: str | None = None


CONTROL_ACTIONS = {
    "disable_legacy_tls": "Disable TLS 1.0/1.1",
    "remove_weak_ciphers": "Remove RC4/3DES",
    "renew_certificates": "Renew/modernize certificates",
    "enforce_forward_secrecy": "Enforce forward secrecy",
    "block_plaintext_email": "Block plaintext email",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_event(event: str, scan_id: str | None, detail: str = "") -> None:
    with db() as c:
        c.execute("INSERT INTO app_events(created_at,event,scan_id,detail) VALUES (?,?,?,?)", (now_iso(), event, scan_id, detail))


def normalized_result(scan_id: str, sessions: list[dict[str, Any]], mode: str, input_file: str | None = None, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    findings = analyze_sessions(sessions)
    summary = summarize(sessions, findings)
    score = posture_score(findings)
    anomalies = anomaly_scores(sessions)
    events = build_events(sessions, findings)
    root_causes = build_root_causes(findings)
    recommendations = build_recommendations(findings)
    result = {
        "scan_id": scan_id,
        "generated_at": now_iso(),
        "mode": mode,
        "input_file": input_file,
        "score": score,
        "posture": label(score),
        "summary": summary,
        "sessions": sessions,
        "findings": findings,
        "events": events,
        "anomalies": anomalies[:5],
        "root_causes": root_causes,
        "ai_insights": ai_insights(findings, anomalies, summary),
        "recommendations": recommendations,
        "metadata": metadata or {},
        "control_catalog": CONTROL_ACTIONS,
    }
    return result


def build_events(sessions: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for s in sessions:
        events.append({"packet": s.get("packet_start", 0), "message": f"{s['protocol']} session detected", "session_id": s["session_id"], "type": "session"})
        if s.get("starttls"):
            events.append({"packet": s.get("packet_start", 0) + 3, "message": f"{s['protocol']} STARTTLS observed", "session_id": s["session_id"], "type": "starttls"})
        if s.get("tls_version") not in {"UNKNOWN", "PLAINTEXT", "NONE"}:
            events.append({"packet": s.get("packet_start", 0) + 6, "message": f"{s['tls_version']} handshake evidence", "session_id": s["session_id"], "type": "tls"})
    for f in findings:
        events.append({"packet": int(sessions_by_id(sessions, f["session_id"]).get("packet_start") or 0) + 1, "message": f"{f['severity']}: {f['title']}", "session_id": f["session_id"], "finding_id": f["finding_id"], "type": "finding"})
    return sorted(events, key=lambda x: x["packet"])


def sessions_by_id(sessions: list[dict[str, Any]], sid: str) -> dict[str, Any]:
    return next((s for s in sessions if s["session_id"] == sid), {})


def build_root_causes(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mapping: dict[str, list[dict[str, Any]]] = {}
    labels = {
        "disable_legacy_tls": "Legacy TLS policy",
        "block_plaintext_email": "Unprotected email transport",
        "remove_weak_ciphers": "Legacy cipher policy",
        "enforce_forward_secrecy": "Static key exchange",
        "renew_certificates": "Certificate lifecycle / identity hygiene",
    }
    for f in findings:
        mapping.setdefault(f["control"], []).append(f)
    out = []
    for control, fs in sorted(mapping.items(), key=lambda x: len(x[1]), reverse=True):
        out.append({"cause": labels.get(control, control), "control": control, "finding_count": len(fs), "findings": [f["finding_id"] for f in fs]})
    return out[:5]


def build_recommendations(findings: list[dict[str, Any]]) -> list[str]:
    seen = set(); out = []
    for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["severity"], 9)):
        if f["recommendation"] not in seen:
            seen.add(f["recommendation"]); out.append(f["recommendation"])
    return out[:8]


def ai_insights(findings: list[dict[str, Any]], anomalies: list[dict[str, Any]], summary: dict[str, Any]) -> list[str]:
    insights = []
    if summary["critical"]:
        insights.append(f"The evidence contains {summary['critical']} critical finding(s); these should be addressed first.")
    if findings:
        most_common = max(summary["categories"].items(), key=lambda x: x[1])[0]
        insights.append(f"{most_common} controls are the dominant source of observed cryptographic risk in this capture.")
    if anomalies:
        insights.append(f"Isolation Forest highlights {anomalies[0]['session_id']} as the highest-anomaly session with score {anomalies[0]['anomaly_score']}.")
    if any(f["control"] == "block_plaintext_email" for f in findings):
        insights.append("Plaintext email access/submission is a direct transport-security concern and creates the strongest evidence-backed exposure in the demonstration capture.")
    insights.append("Risk conclusions are derived from observed protocol/cryptographic evidence; anomaly scores identify unusual profiles and do not by themselves prove compromise.")
    return insights


def save_scan(result: dict[str, Any]) -> dict[str, Any]:
    audit = make_chain(result["scan_id"], result)
    with db() as c:
        c.execute("INSERT OR REPLACE INTO scans(scan_id,created_at,mode,input_file,result_json,audit_json) VALUES (?,?,?,?,?,?)", (
            result["scan_id"], result["generated_at"], result["mode"], result.get("input_file"), json.dumps(result), json.dumps(audit)
        ))
    log_event("scan_completed", result["scan_id"], result["mode"])
    return audit


def load_scan(scan_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    with db() as c:
        row = c.execute("SELECT result_json,audit_json FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Scan not found")
    return json.loads(row[0]), json.loads(row[1])


def demo_sessions() -> list[dict[str, Any]]:
    path = DATA / "demo_evidence.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload["sessions"]


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse((STATIC / "index.html").read_text(encoding="utf-8"))


@app.get("/api/health")
async def health() -> JSONResponse:
    import shutil
    return JSONResponse({
        "app": "SecureMailScope",
        "status": "ok",
        "tshark_available": shutil.which("tshark") is not None,
        "database": str(DB),
        "current_scan_id": CURRENT_SCAN_ID,
        "ai_provider": "local-evidence-copilot",
        "version": "1.0.0",
    })


@app.post("/api/demo")
async def run_demo() -> JSONResponse:
    global CURRENT_SCAN_ID
    scan_id = f"SMS-DEMO-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
    result = normalized_result(scan_id, demo_sessions(), "CONTROLLED_DEMO", "demo_evidence.json", {"source": "bundled synthetic evidence", "pcap_ready": True})
    audit = save_scan(result)
    CURRENT_SCAN_ID = scan_id
    return JSONResponse({"result": result, "audit": audit})


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str) -> JSONResponse:
    result, audit = load_scan(scan_id)
    return JSONResponse({"result": result, "audit": audit})


@app.post("/api/upload")
async def upload(file: UploadFile = File(...)) -> JSONResponse:
    global CURRENT_SCAN_ID
    name = Path(file.filename or "capture.pcap").name
    suffix = Path(name).suffix.lower()
    if suffix not in {".pcap", ".pcapng", ".json"}:
        raise HTTPException(400, "Upload a .pcap, .pcapng or normalized .json evidence file.")
    raw = await file.read()
    if len(raw) > 200 * 1024 * 1024:
        raise HTTPException(413, "Maximum upload size is 200 MB.")
    safe_name = f"{uuid.uuid4().hex}_{name}"
    upload_path = UPLOADS / safe_name
    upload_path.write_bytes(raw)

    if suffix == ".json":
        try:
            payload = json.loads(raw.decode("utf-8"))
            sessions = payload["sessions"]
            result = normalized_result(
                f"SMS-JSON-{datetime.now().strftime('%Y%m%d-%H%M%S')}", sessions, "NORMALIZED_EVIDENCE", name,
                {"source": "uploaded normalized evidence"}
            )
        except Exception as exc:
            raise HTTPException(400, f"Invalid normalized evidence JSON: {exc}") from exc
    else:
        try:
            parsed = analyze_pcap(upload_path)
        except Exception as exc:
            raise HTTPException(422, str(exc)) from exc
        result = normalized_result(
            f"SMS-PCAP-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}",
            parsed["sessions"], "REAL_PCAP_TSHARK", name,
            {k: v for k, v in parsed.items() if k != "sessions"},
        )
    audit = save_scan(result)
    CURRENT_SCAN_ID = result["scan_id"]
    return JSONResponse({"result": result, "audit": audit})


@app.post("/api/what-if")
async def api_what_if(req: WhatIfRequest) -> JSONResponse:
    result, _ = load_scan(req.scan_id)
    return JSONResponse(what_if(result["findings"], req.actions))


@app.post("/api/copilot")
async def api_copilot(req: CopilotRequest) -> JSONResponse:
    result, _ = load_scan(req.scan_id)
    session = sessions_by_id(result["sessions"], req.session_id) if req.session_id else None
    finding = next((f for f in result["findings"] if f["finding_id"] == req.finding_id), None) if req.finding_id else None
    data = copilot_answer(req.question, result, session, finding)
    log_event("copilot_question", req.scan_id, req.question[:200])
    return JSONResponse(data)


@app.get("/api/audit/{scan_id}")
async def audit(scan_id: str) -> JSONResponse:
    _, chain = load_scan(scan_id)
    return JSONResponse({**verify_chain(chain), "audit": chain})


@app.get("/api/report/{scan_id}")
async def report(scan_id: str) -> FileResponse:
    result, audit_chain = load_scan(scan_id)
    out = REPORTS / f"SecureMailScope_{scan_id}.pdf"
    generate_pdf(out, result, audit_chain)
    log_event("report_generated", scan_id, str(out.name))
    return FileResponse(out, media_type="application/pdf", filename=out.name)


@app.get("/api/standards")
async def standards() -> JSONResponse:
    return JSONResponse({
        "standards": [
            {"id": "RFC 9325", "use": "TLS configuration and modern cryptographic guidance"},
            {"id": "RFC 8996", "use": "TLS 1.0 / 1.1 deprecation"},
            {"id": "RFC 8314", "use": "TLS for email access/submission"},
            {"id": "RFC 3207", "use": "SMTP STARTTLS"},
            {"id": "RFC 6125", "use": "Service identity / hostname verification"},
        ]
    })
