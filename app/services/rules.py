from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    category: str
    standard: str
    expected: str
    remediation: str
    description: str


RULES = {
    "legacy_tls": Rule(
        "TLS-001", "Deprecated TLS version negotiated", "HIGH", "Protocol",
        "RFC 8996 / RFC 9325", "TLS 1.2 or TLS 1.3",
        "Disable TLS 1.0/1.1 and enforce TLS 1.2+; prefer TLS 1.3.",
        "TLS 1.0 and TLS 1.1 are deprecated for modern secure communications.",
    ),
    "plaintext": Rule(
        "TLS-002", "Email session observed without TLS protection", "CRITICAL", "Transport",
        "RFC 8314", "TLS-protected transport",
        "Require TLS-protected email access/submission and disable plaintext access where policy permits.",
        "Unencrypted email transport can expose credentials and message content to passive observers.",
    ),
    "weak_cipher": Rule(
        "CRYPTO-001", "Weak / deprecated cipher suite", "HIGH", "Cipher",
        "RFC 9325", "Modern AEAD cipher suite",
        "Remove RC4/3DES and permit modern AEAD suites such as AES-GCM or ChaCha20-Poly1305.",
        "Legacy stream/block ciphers provide weaker security than modern AEAD configurations.",
    ),
    "no_forward_secrecy": Rule(
        "CRYPTO-002", "Forward secrecy not observed", "MEDIUM", "Key Exchange",
        "RFC 9325", "ECDHE/X25519-style ephemeral key exchange",
        "Prefer ephemeral ECDHE/X25519 key exchange to provide forward secrecy.",
        "Ephemeral key exchange limits the value of a later-compromised long-term private key for old traffic.",
    ),
    "expired_cert": Rule(
        "CERT-001", "Expired X.509 certificate", "HIGH", "Certificate",
        "X.509 / TLS operational hygiene", "valid certificate",
        "Renew the certificate and validate the complete trust chain before deployment.",
        "An expired certificate can cause trust failures and indicates poor certificate lifecycle hygiene.",
    ),
    "weak_key": Rule(
        "CERT-002", "Weak public-key size", "HIGH", "Certificate",
        "NIST TLS guidance", "RSA 2048+ or appropriate modern alternative",
        "Replace 1024-bit RSA material with a modern key size/algorithm.",
        "RSA 1024 is below modern recommended security levels.",
    ),
    "sha1": Rule(
        "CERT-003", "SHA-1 certificate signature observed", "MEDIUM", "Certificate",
        "Modern TLS cryptographic guidance", "SHA-256 or stronger",
        "Re-issue the certificate using a modern signature algorithm such as SHA-256 or stronger.",
        "SHA-1 is deprecated for contemporary public-key certificate signatures.",
    ),
    "hostname": Rule(
        "CERT-004", "Certificate identity mismatch", "HIGH", "Certificate",
        "RFC 6125", "Hostname matches certificate identity",
        "Deploy a certificate whose SAN/CN covers the observed mail service hostname.",
        "A hostname mismatch weakens endpoint authentication and can cause client trust failures.",
    ),
    "short_expiry": Rule(
        "CERT-005", "Certificate expires soon", "LOW", "Certificate",
        "Operational hygiene", "> 30 days remaining preferred",
        "Schedule certificate renewal before the remaining validity window becomes critical.",
        "Short remaining validity increases operational risk even when the certificate is currently valid.",
    ),
}


def make_finding(rule_key: str, session: dict[str, Any], observed: str, evidence: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    r = RULES[rule_key]
    item = {
        "rule_id": r.rule_id,
        "session_id": session["session_id"],
        "protocol": session["protocol"],
        "title": r.title,
        "severity": r.severity,
        "category": r.category,
        "observed": observed,
        "expected": r.expected,
        "evidence": evidence,
        "standard": r.standard,
        "recommendation": r.remediation,
        "why_it_matters": r.description,
        "control": {
            "legacy_tls": "disable_legacy_tls",
            "plaintext": "block_plaintext_email",
            "weak_cipher": "remove_weak_ciphers",
            "no_forward_secrecy": "enforce_forward_secrecy",
            "expired_cert": "renew_certificates",
            "weak_key": "renew_certificates",
            "sha1": "renew_certificates",
            "hostname": "renew_certificates",
            "short_expiry": "renew_certificates",
        }[rule_key],
    }
    if extra:
        item.update(extra)
    return item


def analyze_sessions(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seq = 1
    for s in sessions:
        packet_range = f"Packets {s.get('packet_start', '?')}-{s.get('packet_end', '?')}"
        tls = str(s.get("tls_version", "UNKNOWN"))
        cipher = str(s.get("cipher_suite", "NONE"))

        if tls in {"TLS 1.0", "TLS 1.1"}:
            findings.append(make_finding(
                "legacy_tls", s, tls,
                f"{packet_range}: negotiated TLS version = {tls}",
                {"finding_id": f"TLS-{seq:03d}"},
            )); seq += 1

        if tls == "PLAINTEXT":
            findings.append(make_finding(
                "plaintext", s, "PLAINTEXT",
                f"{packet_range}: email payload observed before any TLS handshake",
                {"finding_id": f"TLS-{seq:03d}"},
            )); seq += 1

        if any(x in cipher.upper() for x in ("RC4", "3DES", "DES-CBC")):
            findings.append(make_finding(
                "weak_cipher", s, cipher,
                f"{packet_range}: cipher suite = {cipher}",
                {"finding_id": f"CRYPTO-{seq:03d}"},
            )); seq += 1

        if tls not in {"PLAINTEXT", "UNKNOWN", "NONE"} and not bool(s.get("forward_secrecy")):
            findings.append(make_finding(
                "no_forward_secrecy", s, str(s.get("key_exchange", "unknown")),
                f"{packet_range}: key exchange = {s.get('key_exchange', 'unknown')}",
                {"finding_id": f"CRYPTO-{seq:03d}"},
            )); seq += 1

        if str(s.get("certificate", "")).lower() == "expired":
            findings.append(make_finding(
                "expired_cert", s, f"{s.get('cert_days_left')} days",
                f"{packet_range}: certificate validity indicates expiry",
                {"finding_id": f"CERT-{seq:03d}"},
            )); seq += 1

        if str(s.get("public_key", "")) == "RSA 1024":
            findings.append(make_finding(
                "weak_key", s, "RSA 1024",
                f"{packet_range}: public key = RSA 1024",
                {"finding_id": f"CERT-{seq:03d}"},
            )); seq += 1

        if str(s.get("signature", "")).upper().startswith("SHA-1"):
            findings.append(make_finding(
                "sha1", s, str(s.get("signature")),
                f"{packet_range}: certificate signature = {s.get('signature')}",
                {"finding_id": f"CERT-{seq:03d}"},
            )); seq += 1

        if s.get("hostname_match") is False:
            findings.append(make_finding(
                "hostname", s, "mismatch",
                f"{packet_range}: observed server name not covered by certificate SAN/CN",
                {"finding_id": f"CERT-{seq:03d}"},
            )); seq += 1

        if isinstance(s.get("cert_days_left"), int) and 0 <= s["cert_days_left"] <= 30:
            findings.append(make_finding(
                "short_expiry", s, f"{s['cert_days_left']} days remaining",
                f"{packet_range}: certificate expires within the preferred 30-day operational window",
                {"finding_id": f"CERT-{seq:03d}"},
            )); seq += 1

    return findings
