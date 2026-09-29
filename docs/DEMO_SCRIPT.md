# 6–7 minute SIH26159 demo script

## 1. Open the dashboard
Say: "SecureMailScope takes passive email traffic evidence and converts it into a cryptographic security posture assessment."

## 2. Run Demo Scan
Click **Run Demo Scan**.
Say: "The controlled evidence contains SMTP, IMAP and POP3 sessions. The analyzer normalizes the session evidence before running the rules and anomaly models."

## 3. Session investigation
Select `imap-006` or `smtp-002`.
Point out TLS version, cipher, key exchange, certificate state, signature and packet range.
Say: "Every conclusion is tied back to a session and evidence range rather than being an unexplained score."

## 4. Findings
Click a HIGH or CRITICAL finding.
Say: "The rule engine maps an observed cryptographic fact to a severity, expected state, standard reference and remediation."

## 5. Forensic timeline
Click a timeline event.
Say: "The timeline gives an analyst a compact sequence of protocol, TLS and finding events."

## 6. AI Copilot
Select a risky session and ask: `Why is this risky?`
Then ask: `How do I fix the highest risk findings?`
Say: "The copilot is context-aware and evidence-grounded. It explains observations; it does not claim that an anomaly proves compromise."

## 7. What-if remediation
Select all five controls and click **Simulate Improvement**.
Say: "This is a planning simulator. It re-runs the posture model after suppressing findings addressed by the selected controls; no live server is changed."

## 8. ML anomalies
Point to the anomaly list.
Say: "Isolation Forest highlights sessions whose normalized cryptographic/traffic feature profiles are unusual compared with the capture."

## 9. Audit verification
Click **Verify Audit Chain**.
Say: "The current prototype demonstrates evidence integrity with a chained SHA-256 ledger. A production deployment can anchor the final evidence hash to a permissioned ledger."

## 10. Generate PDF
Click **Generate PDF**.
Say: "The same evidence, findings, recommendations and integrity anchors are packaged into a formal report."
