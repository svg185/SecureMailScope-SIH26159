from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak


def generate_pdf(path: Path, result: dict[str, Any], audit: list[dict[str, Any]]) -> Path:
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=32, leftMargin=32, topMargin=32, bottomMargin=32)
    story: list[Any] = []
    story.append(Paragraph("SecureMailScope", styles["Title"]))
    story.append(Paragraph("SIH26159 — AI-Assisted Cryptographic Security Posture Assessment", styles["Heading2"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"Scan: {escape(result['scan_id'])} | Mode: {escape(result.get('mode', ''))}", styles["Normal"]))
    story.append(Paragraph(f"Generated: {escape(result['generated_at'])}", styles["Normal"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"Overall posture: <b>{result['score']}/100 — {escape(result['posture'])}</b>", styles["Heading2"]))
    s = result["summary"]
    story.append(Paragraph(
        f"Sessions: {s['sessions']} | Secure/Encrypted sessions: {s.get('secure_sessions', 0)} | Findings: {s['findings']} | Critical: {s['critical']} | High: {s['high']} | Medium: {s['medium']} | Low: {s['low']}",
        styles["Normal"],
    ))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Session Inventory", styles["Heading2"]))
    rows = [["Session", "Protocol", "TLS", "Cipher", "Certificate", "Packets"]]
    for x in result["sessions"]:
        rows.append([x["session_id"], x["protocol"], x.get("tls_version", ""), x.get("cipher_suite", ""), x.get("certificate", ""), f"{x.get('packet_start')}-{x.get('packet_end')}"])
    t = Table(rows, repeatRows=1, colWidths=[66, 45, 58, 120, 65, 65])
    t.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0f172a")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("GRID", (0,0), (-1,-1), .3, colors.grey), ("FONTSIZE", (0,0), (-1,-1), 7), ("VALIGN", (0,0), (-1,-1), "TOP")]))
    story.append(t)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Findings", styles["Heading2"]))
    rows = [["ID", "Severity", "Session", "Finding", "Evidence"]]
    for f in result["findings"]:
        rows.append([f["finding_id"], f["severity"], f["session_id"], f["title"], f["evidence"][:95]])
    t = Table(rows, repeatRows=1, colWidths=[50, 50, 60, 145, 165])
    t.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0f172a")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("GRID", (0,0), (-1,-1), .3, colors.grey), ("FONTSIZE", (0,0), (-1,-1), 7), ("VALIGN", (0,0), (-1,-1), "TOP")]))
    story.append(t)
    story.append(PageBreak())

    story.append(Paragraph("AI-Assisted Insights", styles["Heading2"]))
    for text in result.get("ai_insights", []):
        story.append(Paragraph("• " + escape(text), styles["BodyText"]))
        story.append(Spacer(1, 4))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Recommendations", styles["Heading2"]))
    for text in result.get("recommendations", []):
        story.append(Paragraph("• " + escape(text), styles["BodyText"]))
        story.append(Spacer(1, 4))

    story.append(Paragraph("Integrity Evidence", styles["Heading2"]))
    story.append(Paragraph(f"Final evidence hash: {escape(audit[-1]['evidence_hash'])}", styles["BodyText"]))
    story.append(Paragraph(f"Final audit record hash: {escape(audit[-1]['record_hash'])}", styles["BodyText"]))
    story.append(Paragraph("The current prototype uses a chained SHA-256 audit ledger. A production deployment can anchor the final evidence hash to a permissioned ledger.", styles["BodyText"]))
    doc.build(story)
    return path
