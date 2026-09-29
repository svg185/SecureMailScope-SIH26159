# SecureMailScope UI Guide

The dashboard at `http://127.0.0.1:8000` brings scan evidence, risk signals, remediation estimates and audit verification into one view.

## Start an assessment

- Select **Run Demo Scan** to analyze the bundled synthetic evidence without a PCAP or network access.
- Select **Upload PCAP** to analyze a `.pcap`, `.pcapng` or normalized `.json` evidence file. TShark must be installed and available on `PATH` for PCAP files.
- The top status indicator reports whether the backend is available and whether TShark was detected.

## Investigate results

- The summary row shows posture score, session count, finding count and analysis mode.
- Select a session to inspect its endpoints, TLS settings, certificate details and linked findings.
- Select a finding or timeline event to open its evidence, rationale, applicable standard and remediation recommendation.
- Use the severity distribution, root causes and anomaly list to prioritize follow-up. An anomaly is a signal for review, not proof of compromise.

## Explore and verify

- In **What-if Remediation Simulator**, select one or more controls and simulate their projected effect. This is an estimate and does not change a live mail server.
- Ask the **AI Security Copilot** about the current scan or use a suggested question. Answers are grounded in the selected scan evidence and local standards knowledge base.
- Select **Verify Audit Chain** to check the scan's chained audit records.
- Select **Generate PDF** to download the assessment report for the current scan.

The bundled demo evidence is synthetic. Findings from uploaded captures depend on the packets visible to the capture and the protocol fields TShark can decode.