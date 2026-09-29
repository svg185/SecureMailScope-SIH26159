# SIH26159 idea — demo-ready abstract

## Proposed solution
SecureMailScope is an AI-assisted passive network-forensic platform that analyzes PCAP/PCAPNG captures of SMTP, IMAP and POP3 communications. It reconstructs relevant TCP sessions, identifies STARTTLS transitions, extracts TLS and X.509 cryptographic properties exposed by the capture, applies a versioned deterministic policy engine, uses anomaly detection to surface unusual session profiles, and generates an evidence-backed cryptographic security posture score.

## Innovation
1. Evidence-linked findings: every issue maps to a session and packet range.
2. Explainable AI Copilot: explains observations with standards context and remediation guidance.
3. What-if remediation simulator: re-runs the posture model without changing a live server.
4. Configuration/posture continuity: persistent scan history, audit hashes and report integrity.
5. ML anomaly layer: Isolation Forest highlights unusual cryptographic/traffic profiles.

## Demo flow
PCAP/evidence -> sessions -> TLS/certificate facts -> rules -> risk score -> ML anomalies -> AI explanation -> remediation simulation -> integrity verification -> PDF report.

## Prototype boundary
The bundled presentation dataset is synthetic and intentionally contains secure and insecure sessions. Real PCAP/PCAPNG analysis is supported through TShark when installed. The audit layer in the demo is a chained SHA-256 integrity ledger; a production deployment can anchor the final hash to a permissioned blockchain.
