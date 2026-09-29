# SecureMailScope architecture

```text
PCAP/PCAPNG
   |
   v
TShark / evidence parser
   |
   v
TCP stream + email protocol normalization
   |
   +--> TLS/certificate/crypto facts
   |
   v
Deterministic rules -----> evidence-backed findings
   |
   +--> Isolation Forest anomaly signal
   |
   v
Risk / posture model
   |
   +--> local RAG/evidence-grounded Copilot
   +--> what-if remediation
   +--> audit hash chain
   +--> PDF report
   |
   v
FastAPI + SQLite persistence + integrated dashboard
```

The primary SIH workflow is passive PCAP analysis. Live mail-server scanning is intentionally not the product's core analysis path.
