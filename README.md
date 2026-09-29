# SecureMailScope — SIH26159

AI-assisted cryptographic security posture and forensic intelligence prototype for secure email communications.

## What is implemented

- Passive evidence workflow for PCAP/PCAPNG, with a bundled controlled evidence set for offline demonstrations.
- Real PCAP parsing path through TShark when TShark is installed and on PATH.
- SMTP, IMAP and POP3 session identification from TCP ports.
- TLS version, cipher suite, STARTTLS, key exchange and certificate evidence extraction where exposed by the capture.
- Deterministic, explainable cryptographic rule engine with findings linked to sessions and packet ranges.
- Posture score independent from CVSS; severity-weighted and bounded for portfolio/demo comparison.
- Isolation Forest anomaly detection over normalized session features.
- Evidence-grounded AI Copilot with a local RFC knowledge base. Optional Gemini path is supported by environment variables.
- What-if remediation simulator that re-runs the posture model after selected controls are addressed.
- SHA-256 chained audit ledger with verification endpoint.
- PDF assessment reports.
- SQLite persistence so scans and reports survive app restarts.

## Quick start (offline demo)

Windows: double-click `run_demo.bat`.

Linux/macOS/WSL:

```bash
./run_demo.sh
```

Open http://127.0.0.1:8000 and click **Run Demo Scan**.

## Real PCAP mode

Install Wireshark/TShark and ensure `tshark` is on PATH. Then upload a `.pcap` or `.pcapng` file from the UI. The backend groups TCP packets into SMTP/IMAP/POP3 sessions and extracts available TLS evidence.

For best demo reliability, always keep the bundled controlled evidence flow available; a PCAP can omit handshake fields because of capture points, encryption or protocol dissection limitations.

## API

- `GET /api/health`
- `POST /api/demo`
- `POST /api/upload`
- `GET /api/scan/{scan_id}`
- `POST /api/copilot`
- `POST /api/what-if`
- `GET /api/audit/{scan_id}`
- `GET /api/report/{scan_id}`
- `GET /api/standards`

## Security model

Treat uploaded PCAPs as untrusted input. The demo app parses them in a worker/process through TShark. For production, put the analyzer behind a sandboxed worker, resource limits, least privilege and object-storage quarantine.

## Current prototype boundaries

The bundled demo evidence is synthetic and intentionally contains secure and insecure sessions so the full UI can be demonstrated without an Internet dependency. The audit component is a local tamper-evident chained hash ledger; it is not a deployed public blockchain. The AI Copilot defaults to a deterministic local evidence-grounded implementation; an external Gemini provider is optional.
