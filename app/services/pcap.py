from __future__ import annotations

import re
import shutil
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PORT_PROTOCOL = {
    25: "SMTP", 465: "SMTP", 587: "SMTP",
    110: "POP3", 995: "POP3",
    143: "IMAP", 993: "IMAP",
}
CIPHER_MAP = {
    "0x0005": "TLS_RSA_WITH_RC4_128_SHA",
    "0x000a": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "0x002f": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "0x0035": "TLS_RSA_WITH_AES_256_CBC_SHA",
    "0xc013": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "0xc014": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "0xc02f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "0xc030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "0x1301": "TLS_AES_128_GCM_SHA256",
    "0x1302": "TLS_AES_256_GCM_SHA384",
    "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
}
VERSION_MAP = {
    "0x0301": "TLS 1.0", "0x0302": "TLS 1.1", "0x0303": "TLS 1.2", "0x0304": "TLS 1.3",
    "771": "TLS 1.2", "772": "TLS 1.3", "770": "TLS 1.1", "769": "TLS 1.0",
}


def _first(v: Any) -> str | None:
    if isinstance(v, list):
        return str(v[0]) if v else None
    if v is None:
        return None
    return str(v)


def _run_tshark(path: Path) -> list[dict[str, str]]:
    tshark = shutil.which("tshark")
    if not tshark:
        raise RuntimeError("TShark is not installed or is not on PATH. Install Wireshark/TShark to enable real PCAP analysis.")
    fields = [
        "frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
        "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.payload",
        "tls.handshake.version", "tls.record.version", "tls.handshake.ciphersuite",
        "tls.handshake.certificate", "tls.handshake.extensions_server_name",
        "tls.handshake.extensions_key_share_group",
    ]
    cmd = [tshark, "-r", str(path), "-T", "fields", "-E", "separator=|", "-E", "quote=d", "-E", "header=y"]
    for f in fields:
        cmd.extend(["-e", f])
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "TShark failed to parse the capture.")
    lines = proc.stdout.splitlines()
    if not lines:
        return []
    headers = lines[0].strip().strip('"').split("|")
    records = []
    for line in lines[1:]:
        vals = line.strip().strip('"').split("|")
        vals += [""] * (len(headers) - len(vals))
        records.append(dict(zip(headers, vals[:len(headers)])))
    return records


def _run_scapy(path: Path) -> list[dict[str, str]]:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.layers.tls.record import TLS
    from scapy.utils import PcapReader

    records: list[dict[str, str]] = []
    stream_ids: dict[tuple[tuple[str, int], tuple[str, int]], int] = {}
    with PcapReader(str(path)) as packets:
        for frame_number, raw_packet in enumerate(packets, start=1):
            record = {"frame.number": str(frame_number), "frame.time_epoch": str(float(raw_packet.time))}
            raw_bytes = bytes(raw_packet)
            try:
                packet = Ether(raw_bytes)
                if not packet.haslayer(IP) and not packet.haslayer(IPv6) and raw_bytes:
                    ip_version = raw_bytes[0] >> 4
                    if ip_version == 4:
                        packet = IP(raw_bytes)
                    elif ip_version == 6:
                        packet = IPv6(raw_bytes)
            except Exception:
                records.append(record)
                continue

            if not packet.haslayer(TCP) or not (packet.haslayer(IP) or packet.haslayer(IPv6)):
                records.append(record)
                continue

            network = packet[IP] if packet.haslayer(IP) else packet[IPv6]
            tcp = packet[TCP]
            source = (str(network.src), int(tcp.sport))
            destination = (str(network.dst), int(tcp.dport))
            flow = tuple(sorted((source, destination)))
            stream_id = stream_ids.setdefault(flow, len(stream_ids))
            payload = bytes(tcp.payload)
            record.update({
                "ip.src": source[0],
                "ip.dst": destination[0],
                "tcp.srcport": str(source[1]),
                "tcp.dstport": str(destination[1]),
                "tcp.stream": str(stream_id),
                "tcp.payload": payload.hex(),
            })

            if len(payload) >= 5 and payload[0] == 22 and payload[1] == 3:
                try:
                    tls = TLS(payload)
                    messages = tls.msg if isinstance(tls.msg, list) else [tls.msg]
                    for message in messages:
                        if type(message).__name__ == "TLSServerHello":
                            version = int(message.version)
                            cipher = int(message.cipher)
                            if cipher in {0x1301, 0x1302, 0x1303}:
                                version = 772
                            record["tls.handshake.version"] = str(version)
                            record["tls.handshake.ciphersuite"] = f"0x{cipher:04x}"
                except Exception:
                    pass

            records.append(record)
    return records


def _map_version(v: str | None) -> str:
    if not v:
        return "UNKNOWN"
    vv = v.lower().strip()
    for key, val in VERSION_MAP.items():
        if key.lower() in vv:
            return val
    if "tls 1.3" in vv or "0x0304" in vv:
        return "TLS 1.3"
    if "tls 1.2" in vv or "0x0303" in vv:
        return "TLS 1.2"
    if "tls 1.1" in vv or "0x0302" in vv:
        return "TLS 1.1"
    if "tls 1.0" in vv or "0x0301" in vv:
        return "TLS 1.0"
    return v


def _map_cipher(v: str | None) -> str:
    if not v:
        return "NONE"
    vv = v.strip().lower()
    for k, name in CIPHER_MAP.items():
        if k in vv:
            return name
    return v


def _infer_kx(cipher: str, group: str | None) -> tuple[str, bool]:
    up = cipher.upper()
    if "ECDHE" in up or group:
        return (f"X25519/{group}" if group else "ECDHE", True)
    if "DHE" in up:
        return "DHE", True
    if "RSA" in up:
        return "RSA", False
    return "Unknown", False


def _tls_records(records: list[dict[str, str]]) -> list[dict[str, Any]]:
    streams: dict[str, dict[str, Any]] = {}
    for r in records:
        stream = r.get("tcp.stream") or "-"
        src = r.get("ip.src") or r.get("ipv6.src") or "?"
        dst = r.get("ip.dst") or r.get("ipv6.dst") or "?"
        try:
            sp = int(r.get("tcp.srcport") or 0); dp = int(r.get("tcp.dstport") or 0)
        except ValueError:
            sp = dp = 0
        proto = PORT_PROTOCOL.get(dp) or PORT_PROTOCOL.get(sp)
        if not proto:
            continue
        bucket = streams.setdefault(stream, {
            "session_id": f"{proto.lower()}-{stream}", "protocol": proto,
            "src": f"{src}:{sp}", "dst": f"{dst}:{dp}",
            "packet_start": None, "packet_end": None, "packet_count": 0,
            "duration_ms": 0, "tls_version": "UNKNOWN", "cipher_suite": "NONE",
            "key_exchange": "Unknown", "forward_secrecy": False,
            "starttls": False, "certificate": "not-observed", "cert_days_left": None,
            "public_key": "N/A", "signature": "N/A", "hostname_match": True,
            "server_name": None, "certificate_subject": None, "certificate_issuer": None,
            "certificate_sha256": None,
        })
        n = int(r.get("frame.number") or 0)
        bucket["packet_count"] += 1
        bucket["packet_start"] = n if bucket["packet_start"] is None else min(bucket["packet_start"], n)
        bucket["packet_end"] = n if bucket["packet_end"] is None else max(bucket["packet_end"], n)
        epoch = r.get("frame.time_epoch")
        if epoch:
            try:
                bucket.setdefault("_first_ts", float(epoch)); bucket["_last_ts"] = float(epoch)
                bucket["duration_ms"] = round((bucket["_last_ts"] - bucket["_first_ts"]) * 1000)
            except ValueError:
                pass
        for vf in ("tls.handshake.version", "tls.record.version"):
            if r.get(vf):
                mapped = _map_version(r[vf])
                if mapped != "UNKNOWN":
                    bucket["tls_version"] = mapped; break
        if r.get("tls.handshake.ciphersuite"):
            bucket["cipher_suite"] = _map_cipher(r["tls.handshake.ciphersuite"])
        if r.get("tls.handshake.extensions_server_name"):
            bucket["server_name"] = r["tls.handshake.extensions_server_name"]
        if r.get("tls.handshake.extensions_key_share_group"):
            bucket["key_exchange"], bucket["forward_secrecy"] = _infer_kx(bucket["cipher_suite"], r["tls.handshake.extensions_key_share_group"])
        else:
            bucket["key_exchange"], bucket["forward_secrecy"] = _infer_kx(bucket["cipher_suite"], None)

        payload = (r.get("tcp.payload") or "").replace(":", "")
        if payload:
            try:
                text = bytes.fromhex(payload).decode("utf-8", errors="ignore")
            except ValueError:
                text = ""
            upper = text.upper()
            if any(x in upper for x in ("STARTTLS", "STLS")):
                bucket["starttls"] = True

    out = []
    for b in streams.values():
        b.pop("_first_ts", None); b.pop("_last_ts", None)
        if b["tls_version"] == "UNKNOWN" and b["protocol"] in {"SMTP", "IMAP", "POP3"}:
            b["tls_version"] = "PLAINTEXT" if not b["starttls"] and b["dst"].rsplit(":", 1)[-1] in {"25", "110", "143"} else "UNKNOWN"
        out.append(b)
    return sorted(out, key=lambda x: (x["protocol"], x["session_id"]))


def analyze_pcap(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if shutil.which("tshark"):
        records = _run_tshark(p)
        parser = "TShark"
        mode = "REAL_PCAP_TSHARK"
    else:
        records = _run_scapy(p)
        parser = "Scapy fallback (certificate details may be limited)"
        mode = "REAL_PCAP_SCAPY"
    sessions = _tls_records(records)
    if not sessions:
        raise RuntimeError("No SMTP/IMAP/POP3 TCP sessions were found in the capture.")
    return {
        "packet_count": len(records),
        "tcp_streams": len({r.get('tcp.stream') for r in records if r.get('tcp.stream')}),
        "sessions": sessions,
        "mode": mode,
        "parser": parser,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
