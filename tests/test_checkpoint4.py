"""Checkpoint 4 tests: port scanner, banner grabbing, service detection.

No real sockets: the connector is injected via `open_conn`, returning fake
reader/writer pairs. Run with:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import asyncio
import unittest

from wifi_scanner.scanner.models import Host
from wifi_scanner.scanner.port_scan import (
    identify_service,
    probe_port,
    scan_and_annotate,
)


# --------------------------------------------------------------------------- #
# Fake asyncio stream objects
# --------------------------------------------------------------------------- #
class FakeReader:
    def __init__(self, data: bytes = b""):
        self._data = data

    async def read(self, n: int) -> bytes:
        chunk, self._data = self._data[:n], self._data[n:]
        return chunk


class FakeWriter:
    def __init__(self):
        self.written = b""

    def write(self, data: bytes):
        self.written += data

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


def make_open_conn(open_ports: dict[int, bytes]):
    """Return an open_conn coroutine where only `open_ports` accept; the value
    is the banner the fake server sends on first read."""
    async def _open_conn(ip, port, timeout):
        if port not in open_ports:
            raise ConnectionRefusedError(port)
        return FakeReader(open_ports[port]), FakeWriter()
    return _open_conn


class TestIdentifyService(unittest.TestCase):
    def test_ssh_banner(self):
        self.assertEqual(
            identify_service(22, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"),
            "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        )

    def test_http_server_header(self):
        banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
        self.assertEqual(identify_service(80, banner), "HTTP nginx/1.18.0")

    def test_http_without_server_header(self):
        self.assertEqual(identify_service(80, "HTTP/1.0 404 Not Found\r\n"), "HTTP")

    def test_ftp_banner(self):
        self.assertTrue(identify_service(21, "220 ProFTPD Server ready").startswith("FTP"))

    def test_smtp_banner(self):
        self.assertTrue(
            identify_service(25, "220 mail.example.com ESMTP Postfix").startswith("SMTP")
        )

    def test_telnet_by_port(self):
        self.assertEqual(identify_service(23, ""), "Telnet")

    def test_rdp_vnc_by_port(self):
        self.assertEqual(identify_service(3389, ""), "RDP")
        self.assertEqual(identify_service(5900, ""), "VNC")

    def test_empty_banner_falls_back_to_well_known(self):
        self.assertEqual(identify_service(445, ""), "smb")

    def test_unknown_port_empty(self):
        self.assertEqual(identify_service(12345, ""), "open")


class TestProbePort(unittest.TestCase):
    def test_open_port_with_banner(self):
        open_conn = make_open_conn({22: b"SSH-2.0-OpenSSH_9.0\r\n"})
        result = asyncio.run(
            probe_port("10.8.50.1", 22, timeout=1, read_timeout=0.2, open_conn=open_conn)
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.port, 22)
        self.assertIn("OpenSSH_9.0", result.service)

    def test_closed_port_returns_none(self):
        open_conn = make_open_conn({22: b""})
        result = asyncio.run(
            probe_port("10.8.50.1", 80, timeout=1, read_timeout=0.2, open_conn=open_conn)
        )
        self.assertIsNone(result)

    def test_do_banner_false_skips_read(self):
        open_conn = make_open_conn({22: b"SSH-2.0-OpenSSH_9.0\r\n"})
        result = asyncio.run(
            probe_port("10.8.50.1", 22, timeout=1, read_timeout=0.2,
                       open_conn=open_conn, do_banner=False)
        )
        self.assertEqual(result.banner, "")
        # falls back to port-name labelling
        self.assertEqual(result.service, "ssh")


class TestScanAndAnnotate(unittest.TestCase):
    def test_annotates_open_ports_and_services(self):
        host = Host(ip="10.8.50.73", mac="24:5e:be:29:9a:bd")
        open_conn = make_open_conn({
            445: b"",
            8080: b"HTTP/1.1 200 OK\r\nServer: QNAP\r\n\r\n",
        })
        scan_and_annotate(
            [host], [22, 445, 8080], open_conn=open_conn, read_timeout=0.2,
        )
        self.assertEqual(host.open_ports, [445, 8080])
        self.assertEqual(host.services[445], "smb")
        self.assertEqual(host.services[8080], "HTTP QNAP")

    def test_telnet_adds_risk_flag(self):
        host = Host(ip="10.8.50.88", mac="aa:bb:cc:dd:ee:88")
        scan_and_annotate(
            [host], [23, 80], open_conn=make_open_conn({23: b""}), read_timeout=0.2,
        )
        self.assertIn(23, host.open_ports)
        self.assertIn("OPEN_TELNET", host.risk_flags)

    def test_rdp_and_vnc_flags(self):
        host = Host(ip="10.8.50.5", mac="aa:bb:cc:dd:ee:05")
        scan_and_annotate(
            [host], [3389, 5900],
            open_conn=make_open_conn({3389: b"", 5900: b""}), read_timeout=0.2,
        )
        self.assertIn("OPEN_RDP", host.risk_flags)
        self.assertIn("OPEN_VNC", host.risk_flags)

    def test_no_open_ports_leaves_host_clean(self):
        host = Host(ip="10.8.50.9", mac="d6:8e:d3:a9:b6:ef")
        scan_and_annotate(
            [host], [22, 80, 443], open_conn=make_open_conn({}), read_timeout=0.2,
        )
        self.assertEqual(host.open_ports, [])
        self.assertEqual(host.services, {})


if __name__ == "__main__":
    unittest.main()
