from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def canonical_hash(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def make_chain(scan_id: str, result: dict[str, Any]) -> list[dict[str, Any]]:
    evidence_hash = canonical_hash(result)
    actions = [
        "PCAP evidence ingested",
        "Protocol/TLS evidence normalized",
        "Cryptographic rules evaluated",
        "Risk and anomaly analysis generated",
        "AI-assisted assessment generated",
        "Report hash anchored",
    ]
    prev = "0" * 64
    chain: list[dict[str, Any]] = []
    for idx, action in enumerate(actions, 1):
        ts = datetime.now(timezone.utc).isoformat()
        payload = {"scan_id": scan_id, "index": idx, "previous_hash": prev, "evidence_hash": evidence_hash, "action": action, "timestamp": ts}
        record_hash = canonical_hash(payload)
        item = dict(payload)
        item["record_hash"] = record_hash
        chain.append(item)
        prev = record_hash
    return chain


def verify_chain(chain: list[dict[str, Any]]) -> dict[str, Any]:
    prev = "0" * 64
    failures: list[int] = []
    for entry in chain:
        payload = {k: entry[k] for k in ("scan_id", "index", "previous_hash", "evidence_hash", "action", "timestamp")}
        expected = canonical_hash(payload)
        if entry.get("previous_hash") != prev or entry.get("record_hash") != expected:
            failures.append(int(entry.get("index", -1)))
        prev = entry.get("record_hash", "")
    return {"verified": not failures, "failed_indices": failures, "records": len(chain)}
