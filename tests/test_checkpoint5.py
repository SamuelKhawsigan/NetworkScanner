"""Checkpoint 5 tests: protocol prober parsers + orchestration.

No network: parsers are exercised against hand-built byte/text fixtures, and
the orchestrator is tested with patched probers. Run with:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import struct
import unittest
from unittest import mock

from wifi_scanner.scanner import protocols as P
from wifi_scanner.scanner.models import Host
from wifi_scanner.scanner.smb_messages import SMB2_NEGOTIATE, smb2_session_setup


# --------------------------------------------------------------------------- #
# SNMP
# --------------------------------------------------------------------------- #
def make_snmp_response(oid: str, value: str, tag: int = 0x04) -> bytes:
    varbind = P._tlv(0x30, P._tlv(0x06, P._encode_oid(oid)) + P._tlv(tag, value.encode()))
    pdu = P._tlv(
        0xA2,
        P._tlv(0x02, b"\x01") + P._tlv(0x02, b"\x00")
        + P._tlv(0x02, b"\x00") + P._tlv(0x30, varbind),
    )
    return P._tlv(0x30, P._tlv(0x02, b"\x00") + P._tlv(0x04, b"public") + pdu)


class TestSnmp(unittest.TestCase):
    def test_oid_encoding(self):
        # 1.3.6.1.2.1.1.1.0 -> standard sysDescr encoding
        self.assertEqual(
            P._encode_oid("1.3.6.1.2.1.1.1.0").hex(), "2b06010201010100"
        )

    def test_build_get_is_sequence(self):
        pkt = P.build_snmp_get("public", "1.3.6.1.2.1.1.1.0")
        self.assertEqual(pkt[0], 0x30)            # SEQUENCE
        self.assertIn(b"public", pkt)

    def test_parse_octet_string(self):
        resp = make_snmp_response("1.3.6.1.2.1.1.1.0", "RouterOS RB750")
        self.assertEqual(P.parse_snmp_response(resp), "RouterOS RB750")

    def test_parse_garbage_returns_none(self):
        self.assertIsNone(P.parse_snmp_response(b"\x00\x01\x02"))

    def test_probe_uses_first_working_community(self):
        def fake_get(ip, comm, oid, timeout):
            if comm != "public":
                return None
            return {"1.3.6.1.2.1.1.1.0": "RouterOS", "1.3.6.1.2.1.1.5.0": "gw-office"}.get(oid)
        res = P.snmp_probe("10.8.50.1", snmp_get_fn=fake_get)
        self.assertEqual(res.community, "public")
        self.assertEqual(res.sys_descr, "RouterOS")
        self.assertEqual(res.sys_name, "gw-office")
        self.assertTrue(res.default_community)

    def test_probe_returns_none_when_silent(self):
        self.assertIsNone(P.snmp_probe("10.8.50.1", snmp_get_fn=lambda *a: None))


# --------------------------------------------------------------------------- #
# NetBIOS
# --------------------------------------------------------------------------- #
def make_nbns_response(names) -> bytes:
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    answer_name = b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00"
    rdata = bytes([len(names)])
    for name, suffix, group in names:
        padded = name.encode().ljust(15, b"\x20")[:15]
        flags = 0x8400 if group else 0x0400
        rdata += padded + bytes([suffix]) + struct.pack(">H", flags)
    rdata += b"\x00" * 6                          # truncated statistics
    answer = answer_name + struct.pack(">HHIH", 0x0021, 0x0001, 0, len(rdata)) + rdata
    return header + answer


class TestNetbios(unittest.TestCase):
    def test_parse_names(self):
        data = make_nbns_response([
            ("MYPC", 0x00, False),
            ("WORKGROUP", 0x00, True),
        ])
        info = P.parse_nbns_response(data)
        self.assertEqual(info.name, "MYPC")
        self.assertEqual(info.workgroup, "WORKGROUP")
        self.assertIn("MYPC", info.names)

    def test_too_short(self):
        self.assertIsNone(P.parse_nbns_response(b"\x00" * 10))

    def test_query_constant_shape(self):
        self.assertEqual(len(P.NETBIOS_NODE_STATUS), 50)
        self.assertTrue(P.NETBIOS_NODE_STATUS.endswith(b"\x00\x21\x00\x01"))


# --------------------------------------------------------------------------- #
# SMB / NTLM
# --------------------------------------------------------------------------- #
def make_ntlm_challenge(av_pairs) -> bytes:
    ti = b""
    for av_id, text in av_pairs:
        value = text.encode("utf-16-le")
        ti += struct.pack("<HH", av_id, len(value)) + value
    ti += struct.pack("<HH", 0, 0)               # EOL
    header = bytearray(48)
    header[0:8] = b"NTLMSSP\x00"
    header[8:12] = b"\x02\x00\x00\x00"
    header[40:42] = struct.pack("<H", len(ti))
    header[42:44] = struct.pack("<H", len(ti))
    header[44:48] = struct.pack("<I", 48)        # TargetInfo offset
    return bytes(header) + ti


class TestSmb(unittest.TestCase):
    def test_parse_ntlm_challenge(self):
        blob = make_ntlm_challenge([
            (1, "WIN-PC"), (2, "CORP"),
            (3, "win-pc.corp.local"), (4, "corp.local"),
        ])
        info = P.parse_ntlm_challenge(blob)
        self.assertEqual(info.computer_name, "WIN-PC")
        self.assertEqual(info.domain, "CORP")
        self.assertEqual(info.dns_computer, "win-pc.corp.local")
        self.assertEqual(info.dns_domain, "corp.local")

    def test_parse_ntlm_finds_embedded_blob(self):
        blob = b"\x00\x11garbage" + make_ntlm_challenge([(1, "NAS01")])
        self.assertEqual(P.parse_ntlm_challenge(blob).computer_name, "NAS01")

    def test_not_a_challenge(self):
        self.assertIsNone(P.parse_ntlm_challenge(b"no ntlm here"))

    def test_smb2_messages_have_signature(self):
        self.assertTrue(SMB2_NEGOTIATE.startswith(b"\xfeSMB"))
        ss = smb2_session_setup(b"\x00\x01\x02\x03")
        self.assertTrue(ss.startswith(b"\xfeSMB"))
        self.assertIn(b"\x00\x01\x02\x03", ss)


# --------------------------------------------------------------------------- #
# mDNS / DNS
# --------------------------------------------------------------------------- #
def _enc_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def make_mdns_response() -> bytes:
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 2, 0, 0)
    ptr_target = _enc_name("_ipp._tcp.local")
    a1 = (_enc_name("_services._dns-sd._udp.local")
          + struct.pack(">HHIH", 12, 1, 120, len(ptr_target)) + ptr_target)
    a2 = (_enc_name("myprinter.local")
          + struct.pack(">HHIH", 1, 1, 120, 4) + bytes([10, 8, 50, 12]))
    return header + a1 + a2


class TestMdns(unittest.TestCase):
    def test_build_query_ptr(self):
        q = P.build_dns_query("_services._dns-sd._udp.local")
        self.assertTrue(q.endswith(b"\x00\x0c\x00\x01"))   # PTR / IN

    def test_parse_services_and_hostname(self):
        info = P.parse_mdns_response(make_mdns_response())
        self.assertIn("_ipp._tcp.local", info.services)
        self.assertEqual(info.hostname, "myprinter")

    def test_empty_response(self):
        self.assertIsNone(P.parse_mdns_response(struct.pack(">HHHHHH", 0, 0, 0, 0, 0, 0)))


# --------------------------------------------------------------------------- #
# SSDP / UPnP
# --------------------------------------------------------------------------- #
class TestUpnp(unittest.TestCase):
    def test_parse_ssdp_headers(self):
        text = ("HTTP/1.1 200 OK\r\nLOCATION: http://10.8.50.5:80/desc.xml\r\n"
                "SERVER: Linux/3.x UPnP/1.0\r\n\r\n")
        headers = P.parse_ssdp_headers(text)
        self.assertEqual(headers["location"], "http://10.8.50.5:80/desc.xml")
        self.assertIn("upnp", headers["server"].lower())

    def test_parse_upnp_xml(self):
        xml = ("<root><device><manufacturer>Sonos</manufacturer>"
               "<modelName>Play:1</modelName><modelNumber>S1</modelNumber>"
               "<deviceType>urn:schemas-upnp-org:device:ZonePlayer:1</deviceType>"
               "<friendlyName>Living Room</friendlyName></device></root>")
        fields = P.parse_upnp_xml(xml)
        self.assertEqual(fields["manufacturer"], "Sonos")
        self.assertEqual(fields["modelName"], "Play:1")
        self.assertEqual(fields["friendlyName"], "Living Room")


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
class TestHttp(unittest.TestCase):
    def test_parse_title_and_server(self):
        headers = {"server": "nginx/1.18.0"}
        body = "<html><head><title>  Router  Admin </title></head></html>"
        info = P.parse_http(headers, body, port=80)
        self.assertEqual(info.server, "nginx/1.18.0")
        self.assertEqual(info.title, "Router Admin")

    def test_pattern_detection(self):
        info = P.parse_http({"server": "Mikrotik RouterOS"}, "<title>x</title>", 80)
        self.assertIn("MikroTik RouterOS", info.patterns)

    def test_body_pattern(self):
        info = P.parse_http({}, "<title>Hikvision Web</title> login", 80)
        self.assertIn("Hikvision", info.patterns)

    def test_http_probe_injected(self):
        def fetch(url, timeout):
            return {"server": "QNAP"}, "<title>QTS</title>"
        info = P.http_probe("10.8.50.73", 8080, fetch_fn=fetch)
        self.assertEqual(info.server, "QNAP")
        self.assertEqual(info.title, "QTS")


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
class TestProbeHost(unittest.TestCase):
    def test_snmp_sets_hostname_and_default_flag(self):
        host = Host(ip="10.8.50.1", mac="78:9a:18:be:5c:41")
        snmp = P.SnmpResult(community="public", sys_descr="RouterOS",
                            sys_name="gw-office", default_community=True)
        with mock.patch.object(P, "snmp_probe", return_value=snmp), \
             mock.patch.object(P, "netbios_probe", return_value=None), \
             mock.patch.object(P, "mdns_probe", return_value=None), \
             mock.patch.object(P, "upnp_probe", return_value=None):
            P.probe_host(host, do_udp=True)
        self.assertEqual(host.hostname, "gw-office")
        self.assertIn("DEFAULT_SNMP", host.risk_flags)
        self.assertIn("snmp_sysdescr", host.fingerprint_sources)
        self.assertIs(host.signals["snmp"], snmp)

    def test_smb_runs_only_when_445_open(self):
        host = Host(ip="10.8.50.73", mac="24:5e:be:29:9a:bd", open_ports=[445])
        smb = P.SmbInfo(computer_name="NAS01")
        with mock.patch.object(P, "snmp_probe", return_value=None), \
             mock.patch.object(P, "netbios_probe", return_value=None), \
             mock.patch.object(P, "mdns_probe", return_value=None), \
             mock.patch.object(P, "upnp_probe", return_value=None), \
             mock.patch.object(P, "smb_probe", return_value=smb) as smb_mock:
            P.probe_host(host)
        smb_mock.assert_called_once()
        self.assertEqual(host.hostname, "NAS01")

    def test_no_snmp_skips_snmp(self):
        host = Host(ip="10.8.50.9", mac="d6:8e:d3:a9:b6:ef")
        with mock.patch.object(P, "snmp_probe") as snmp_mock, \
             mock.patch.object(P, "netbios_probe", return_value=None), \
             mock.patch.object(P, "mdns_probe", return_value=None), \
             mock.patch.object(P, "upnp_probe", return_value=None):
            P.probe_host(host, do_snmp=False)
        snmp_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
