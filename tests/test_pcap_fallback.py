import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter

from app.services.pcap import analyze_pcap


class PcapFallbackTests(unittest.TestCase):
    def test_scapy_fallback_parses_email_session_without_tshark(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = Path(temp_dir) / "email.pcap"
            writer = PcapWriter(str(capture), sync=True)
            writer.write(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=52000, dport=25) / Raw(load=b"MAIL FROM:<a@example.test>\r\n"))
            writer.write(Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01") / IP(src="192.0.2.20", dst="192.0.2.10") / TCP(sport=25, dport=52000) / Raw(load=b"250 OK\r\n"))
            writer.close()

            with patch("app.services.pcap.shutil.which", return_value=None):
                result = analyze_pcap(capture)

        self.assertEqual(result["parser"], "Scapy fallback (certificate details may be limited)")
        self.assertEqual(result["mode"], "REAL_PCAP_SCAPY")
        self.assertEqual(result["packet_count"], 2)
        self.assertEqual(len(result["sessions"]), 1)
        self.assertEqual(result["sessions"][0]["protocol"], "SMTP")
        self.assertEqual(result["sessions"][0]["tls_version"], "PLAINTEXT")


if __name__ == "__main__":
    unittest.main()