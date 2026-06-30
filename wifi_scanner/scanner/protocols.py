"""Protocol probers: NetBIOS, mDNS, SMB, SNMP, UPnP/SSDP, HTTP(S).

Each prober is split into a **pure parser** (tested against captured byte/text
samples, no I/O) and a thin network function whose socket layer is injectable.
Everything uses plain stdlib sockets / urllib so it stays portable across
Linux/macOS/Windows (see project memory) — no scapy, no root.

Results are small dataclasses; the orchestrator stores them on Host.signals for
the fingerprint and classifier stages to consume.
"""

from __future__ import annotations

import re
import socket
import struct
import urllib.request
from dataclasses import dataclass, field

from .. import config
from .models import Host


def _udp_socket() -> socket.socket:
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


# =========================================================================== #
# SNMP (UDP 161) — manual SNMPv1 GET / BER
# =========================================================================== #
def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _encode_subid(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    stack = []
    while n:
        stack.insert(0, n & 0x7F)
        n >>= 7
    for i in range(len(stack) - 1):
        stack[i] |= 0x80
    return bytes(stack)


def _encode_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        out += _encode_subid(p)
    return out


def build_snmp_get(community: str, oid: str, request_id: int = 1) -> bytes:
    """Build an SNMPv1 GET-REQUEST for a single OID."""
    varbind = _tlv(0x30, _tlv(0x06, _encode_oid(oid)) + _tlv(0x05, b""))
    pdu = _tlv(
        0xA0,
        _tlv(0x02, bytes([request_id]))
        + _tlv(0x02, b"\x00")               # error-status
        + _tlv(0x02, b"\x00")               # error-index
        + _tlv(0x30, varbind),
    )
    return _tlv(
        0x30,
        _tlv(0x02, b"\x00") + _tlv(0x04, community.encode()) + pdu,
    )


def _read_tlv(data: bytes, i: int = 0):
    """Return (tag, value_bytes, next_index)."""
    tag = data[i]
    i += 1
    length = data[i]
    i += 1
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(data[i:i + nbytes], "big")
        i += nbytes
    return tag, data[i:i + length], i + length


def parse_snmp_response(data: bytes) -> str | None:
    """Extract the first varbind value from an SNMP response, as text."""
    try:
        _, seq, _ = _read_tlv(data)                       # outer SEQUENCE
        _, _ver, j = _read_tlv(seq, 0)                    # version
        _, _comm, j = _read_tlv(seq, j)                   # community
        _, pdu, _ = _read_tlv(seq, j)                     # response PDU
        _, _rid, p = _read_tlv(pdu, 0)
        _, err, p = _read_tlv(pdu, p)                     # error-status
        _, _eidx, p = _read_tlv(pdu, p)
        _, vbl, _ = _read_tlv(pdu, p)                     # varbind list
        _, vb, _ = _read_tlv(vbl, 0)                      # first varbind
        _, _oid, r = _read_tlv(vb, 0)
        tag, val, _ = _read_tlv(vb, r)                    # value
    except (IndexError, ValueError):
        return None
    if err and err != b"\x00":
        return None
    if tag == 0x04:                                       # OCTET STRING
        return val.decode("latin-1", "replace") or None
    if tag == 0x02:                                       # INTEGER
        return str(int.from_bytes(val, "big")) if val else None
    if tag in (0x05, 0x80, 0x81, 0x82):                   # NULL / noSuch / endOfMib
        return None
    return val.decode("latin-1", "replace") or None if val else None


@dataclass
class SnmpResult:
    community: str | None = None
    sys_descr: str | None = None
    sys_name: str | None = None
    sys_location: str | None = None
    sys_contact: str | None = None
    default_community: bool = False


def snmp_get(ip: str, community: str, oid: str, timeout: float = 1.0,
             sock_factory=None) -> str | None:
    sock = (sock_factory or _udp_socket)()
    try:
        sock.settimeout(timeout)
        sock.sendto(build_snmp_get(community, oid), (ip, 161))
        data, _ = sock.recvfrom(4096)
        return parse_snmp_response(data)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


def snmp_probe(ip: str, communities=None, timeout: float = 1.0,
               snmp_get_fn=None) -> SnmpResult | None:
    """Try community strings until one answers sysDescr, then collect the rest."""
    communities = communities or config.SNMP_COMMUNITIES
    getter = snmp_get_fn or snmp_get
    for comm in communities:
        descr = getter(ip, comm, config.SNMP_OIDS["sysDescr"], timeout)
        if descr:
            return SnmpResult(
                community=comm,
                sys_descr=descr,
                sys_name=getter(ip, comm, config.SNMP_OIDS["sysName"], timeout),
                sys_location=getter(ip, comm, config.SNMP_OIDS["sysLocation"], timeout),
                sys_contact=getter(ip, comm, config.SNMP_OIDS["sysContact"], timeout),
                default_community=comm in ("public", "private"),
            )
    return None


# =========================================================================== #
# NetBIOS (UDP 137) — node status request
# =========================================================================== #
# Header (trn=0, flags=0, qd=1) + encoded '*' name + NBSTAT(0x21)/IN(0x0001).
NETBIOS_NODE_STATUS = (
    bytes.fromhex("000000000001000000000000")
    + b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
    + bytes.fromhex("00210001")
)


@dataclass
class NetbiosInfo:
    name: str | None = None
    workgroup: str | None = None
    names: list[str] = field(default_factory=list)


def parse_nbns_response(data: bytes) -> NetbiosInfo | None:
    """Parse a NBSTAT response into workstation name + workgroup + all names."""
    if len(data) < 57:
        return None
    i = 12                                                # skip header
    while i < len(data) and data[i] != 0:                 # skip echoed name
        i += data[i] + 1
    i += 1 + 2 + 2 + 4 + 2                                # null + type+class+ttl+rdlen
    if i >= len(data):
        return None
    count = data[i]
    i += 1
    names: list[tuple[str, int, bool]] = []
    for _ in range(count):
        if i + 18 > len(data):
            break
        raw = data[i:i + 15].decode("latin-1", "replace").rstrip(" \x00")
        suffix = data[i + 15]
        flags = int.from_bytes(data[i + 16:i + 18], "big")
        names.append((raw, suffix, bool(flags & 0x8000)))
        i += 18
    workstation = next((n for n, s, g in names if s == 0x00 and not g), None)
    workgroup = next((n for n, s, g in names if s == 0x00 and g), None)
    return NetbiosInfo(name=workstation, workgroup=workgroup,
                       names=[n for n, _, _ in names])


def netbios_probe(ip: str, timeout: float = 1.0, sock_factory=None) -> NetbiosInfo | None:
    sock = (sock_factory or _udp_socket)()
    try:
        sock.settimeout(timeout)
        sock.sendto(NETBIOS_NODE_STATUS, (ip, 137))
        data, _ = sock.recvfrom(4096)
        return parse_nbns_response(data)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


# =========================================================================== #
# SMB (TCP 445) — SMB2 negotiate + NTLMSSP challenge parse
# =========================================================================== #
@dataclass
class SmbInfo:
    computer_name: str | None = None
    domain: str | None = None
    dns_computer: str | None = None
    dns_domain: str | None = None


def parse_ntlm_challenge(blob: bytes) -> SmbInfo | None:
    """Extract target-info names from an NTLMSSP CHALLENGE (type 2) message."""
    start = blob.find(b"NTLMSSP\x00")
    if start < 0 or blob[start + 8:start + 12] != b"\x02\x00\x00\x00":
        return None
    ti_len = int.from_bytes(blob[start + 40:start + 42], "little")
    ti_off = int.from_bytes(blob[start + 44:start + 48], "little")
    p = start + ti_off
    end = p + ti_len
    info: dict[int, str] = {}
    while p + 4 <= end and p + 4 <= len(blob):
        av_id = int.from_bytes(blob[p:p + 2], "little")
        av_len = int.from_bytes(blob[p + 2:p + 4], "little")
        p += 4
        value = blob[p:p + av_len]
        p += av_len
        if av_id == 0:                                    # MsvAvEOL
            break
        info[av_id] = value.decode("utf-16-le", "replace")
    if not info:
        return None
    return SmbInfo(
        computer_name=info.get(1),
        domain=info.get(2),
        dns_computer=info.get(3),
        dns_domain=info.get(4),
    )


# Minimal SMB2 NEGOTIATE and SESSION_SETUP (with NTLMSSP NEGOTIATE) requests,
# each prefixed with the 4-byte direct-TCP length header. Captured constants.
_NTLMSSP_NEGOTIATE = (
    b"NTLMSSP\x00\x01\x00\x00\x00\x97\x82\x08\xe2"
    + b"\x00" * 24
)


def _smb2_wrap(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def smb_probe(ip: str, timeout: float = 2.0, conn_factory=None) -> SmbInfo | None:
    """Negotiate SMB2 and parse the NTLMSSP challenge for host identity.

    `conn_factory(ip, port, timeout)` returns a connected socket (injectable).
    Returns None if SMB isn't usable or no challenge is returned.
    """
    from .smb_messages import SMB2_NEGOTIATE, smb2_session_setup

    connect = conn_factory or (lambda i, p, t: socket.create_connection((i, p), t))
    try:
        sock = connect(ip, 445, timeout)
    except OSError:
        return None
    try:
        sock.settimeout(timeout)
        sock.sendall(_smb2_wrap(SMB2_NEGOTIATE))
        _ = _recv_smb(sock)
        sock.sendall(_smb2_wrap(smb2_session_setup(_NTLMSSP_NEGOTIATE)))
        resp = _recv_smb(sock)
        return parse_ntlm_challenge(resp) if resp else None
    except (OSError, socket.timeout):
        return None
    finally:
        sock.close()


def _recv_smb(sock) -> bytes:
    """Read one direct-TCP SMB frame (4-byte big-endian length prefix)."""
    header = _recv_n(sock, 4)
    if len(header) < 4:
        return b""
    length = struct.unpack(">I", header)[0] & 0x00FFFFFF
    return _recv_n(sock, length)


def _recv_n(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


# =========================================================================== #
# mDNS (UDP 5353) — DNS-SD service enumeration
# =========================================================================== #
@dataclass
class MdnsInfo:
    hostname: str | None = None
    services: list[str] = field(default_factory=list)


def build_dns_query(qname: str, qtype: int = 12) -> bytes:
    """Build a DNS query (qtype 12 = PTR)."""
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    body = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".") if p)
    return header + body + b"\x00" + struct.pack(">HH", qtype, 1)


def _read_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels: list[str] = []
    jumped = False
    next_offset = offset
    pos = offset
    guard = 0
    while pos < len(data) and guard < 128:
        guard += 1
        length = data[pos]
        if length == 0:
            pos += 1
            if not jumped:
                next_offset = pos
            break
        if length & 0xC0 == 0xC0:                         # compression pointer
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                next_offset = pos + 2
            jumped = True
            pos = pointer
            continue
        labels.append(data[pos + 1:pos + 1 + length].decode("latin-1", "replace"))
        pos += 1 + length
    return ".".join(labels), next_offset


def parse_mdns_response(data: bytes) -> MdnsInfo | None:
    """Pull service types (PTR targets) and a hostname (A/AAAA owner) out."""
    if len(data) < 12:
        return None
    qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
    offset = 12
    for _ in range(qd):                                   # skip questions
        _, offset = _read_dns_name(data, offset)
        offset += 4
    services: list[str] = []
    hostname: str | None = None
    for _ in range(an + ns + ar):
        if offset + 1 > len(data):
            break
        name, offset = _read_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata_start = offset
        if rtype == 12:                                   # PTR
            target, _ = _read_dns_name(data, rdata_start)
            if target and target not in services:
                services.append(target)
        elif rtype in (1, 28) and name.endswith(".local"):  # A / AAAA
            hostname = hostname or name[:-len(".local")]
        offset = rdata_start + rdlen
    if not services and not hostname:
        return None
    return MdnsInfo(hostname=hostname, services=services)


def mdns_probe(ip: str, timeout: float = 1.0, sock_factory=None) -> MdnsInfo | None:
    sock = (sock_factory or _udp_socket)()
    try:
        sock.settimeout(timeout)
        query = build_dns_query("_services._dns-sd._udp.local")
        sock.sendto(query, (ip, 5353))
        data, _ = sock.recvfrom(8192)
        return parse_mdns_response(data)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


# =========================================================================== #
# UPnP / SSDP (UDP 1900 + HTTP device description)
# =========================================================================== #
SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode()


@dataclass
class UpnpInfo:
    location: str | None = None
    server: str | None = None
    manufacturer: str | None = None
    model_name: str | None = None
    model_number: str | None = None
    device_type: str | None = None
    friendly_name: str | None = None


def parse_ssdp_headers(text: str) -> dict[str, str]:
    """Parse an SSDP/HTTP header block into a lowercased-key dict."""
    headers: dict[str, str] = {}
    for line in text.split("\r\n")[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return headers


_XML_TAGS = ("manufacturer", "modelName", "modelNumber", "deviceType", "friendlyName")


def parse_upnp_xml(xml: str) -> dict[str, str]:
    """Pull common device-description fields out of UPnP XML."""
    found: dict[str, str] = {}
    for tag in _XML_TAGS:
        match = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.IGNORECASE | re.DOTALL)
        if match:
            found[tag] = match.group(1).strip()
    return found


def upnp_probe(ip: str, timeout: float = 2.0, sock_factory=None,
               fetch_fn=None) -> UpnpInfo | None:
    """Unicast SSDP M-SEARCH to a host, then fetch + parse its description XML."""
    sock = (sock_factory or _udp_socket)()
    try:
        sock.settimeout(timeout)
        sock.sendto(SSDP_MSEARCH, (ip, 1900))
        data, _ = sock.recvfrom(2048)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()

    headers = parse_ssdp_headers(data.decode("latin-1", "replace"))
    info = UpnpInfo(location=headers.get("location"), server=headers.get("server"))
    if info.location:
        xml = (fetch_fn or _http_get_text)(info.location, timeout)
        if xml:
            fields = parse_upnp_xml(xml)
            info.manufacturer = fields.get("manufacturer")
            info.model_name = fields.get("modelName")
            info.model_number = fields.get("modelNumber")
            info.device_type = fields.get("deviceType")
            info.friendly_name = fields.get("friendlyName")
    return info


# =========================================================================== #
# HTTP(S) probing
# =========================================================================== #
@dataclass
class HttpInfo:
    port: int = 0
    server: str | None = None
    title: str | None = None
    patterns: list[str] = field(default_factory=list)
    has_login_form: bool = False


# Substring -> product/vendor hint for admin pages / device UIs.
HTTP_PATTERNS = {
    "dd-wrt": "DD-WRT", "openwrt": "OpenWrt", "tomato": "Tomato",
    "cisco ios": "Cisco IOS", "routeros": "MikroTik RouterOS",
    "jetdirect": "HP JetDirect", "hp laserjet": "HP LaserJet",
    "hikvision": "Hikvision", "dahua": "Dahua", "ubiquiti": "Ubiquiti",
    "unifi": "Ubiquiti UniFi", "synology": "Synology", "qnap": "QNAP",
    "netgear": "Netgear", "tp-link": "TP-Link", "fritz!box": "AVM FRITZ!Box",
}

# Devices whose HTTP admin pages are known to ship with default credentials.
_WEAK_CREDS_DEVICES = {
    "DD-WRT", "OpenWrt", "Tomato", "Cisco IOS", "MikroTik RouterOS",
    "HP JetDirect", "HP LaserJet", "Hikvision", "Dahua",
    "Synology", "QNAP", "Netgear", "TP-Link", "AVM FRITZ!Box",
}

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
# A password input in the response body strongly suggests an admin login page.
_LOGIN_FORM_RE = re.compile(r'type\s*=\s*["\']password["\']', re.IGNORECASE)


def parse_http(headers: dict[str, str], body: str, port: int = 0) -> HttpInfo:
    """Extract Server header, <title>, known device patterns, and login-form presence."""
    info = HttpInfo(port=port, server=headers.get("server"))
    match = _TITLE_RE.search(body)
    if match:
        info.title = re.sub(r"\s+", " ", match.group(1)).strip()[:80]
    haystack = (info.server or "").lower() + " " + body.lower()
    for needle, label in HTTP_PATTERNS.items():
        if needle in haystack and label not in info.patterns:
            info.patterns.append(label)
    info.has_login_form = bool(_LOGIN_FORM_RE.search(body))
    return info


def _http_get_text(url: str, timeout: float) -> str | None:
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "wifi-scanner/0.1"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read(8192).decode("latin-1", "replace")
    except Exception:
        return None


def http_probe(ip: str, port: int, timeout: float = 2.0, fetch_fn=None) -> HttpInfo | None:
    """GET / over HTTP or HTTPS and parse the response."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    fetcher = fetch_fn or _http_get_full
    result = fetcher(url, timeout)
    if result is None:
        return None
    headers, body = result
    return parse_http(headers, body, port)


def _http_get_full(url: str, timeout: float):
    """Return (headers_dict, body_text) or None. TLS verification disabled —
    device certs are typically self-signed."""
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "wifi-scanner/0.1"})
        with urllib.request.urlopen(request, timeout=timeout, context=ctx) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.read(16384).decode("latin-1", "replace")
            return headers, body
    except Exception:
        return None


# =========================================================================== #
# Orchestration
# =========================================================================== #
def probe_host(host: Host, *, do_snmp: bool = True, do_udp: bool = True,
               timeout: float = 1.5) -> None:
    """Run the relevant probers for a host and record signals + hostname/flags.

    TCP probers (SMB/HTTP) run only when their port is open; UDP probers
    (SNMP/NetBIOS/mDNS/UPnP) are best-effort since UDP services don't show up
    in a TCP port scan.
    """
    open_ports = set(host.open_ports)

    if do_snmp:
        snmp = snmp_probe(host.ip, timeout=timeout)
        if snmp:
            host.signals["snmp"] = snmp
            _add_source(host, "snmp_sysdescr")
            if snmp.sys_name and not host.hostname:
                host.hostname = snmp.sys_name
            if snmp.default_community and "DEFAULT_SNMP" not in host.risk_flags:
                host.risk_flags.append("DEFAULT_SNMP")

    if do_udp:
        nb = netbios_probe(host.ip, timeout=timeout)
        if nb:
            host.signals["netbios"] = nb
            _add_source(host, "netbios")
            if nb.name and not host.hostname:
                host.hostname = nb.name

        mdns = mdns_probe(host.ip, timeout=timeout)
        if mdns:
            host.signals["mdns"] = mdns
            _add_source(host, "mdns")
            if mdns.hostname and not host.hostname:
                host.hostname = mdns.hostname

        upnp = upnp_probe(host.ip, timeout=timeout)
        if upnp and (upnp.manufacturer or upnp.model_name or upnp.friendly_name):
            host.signals["upnp"] = upnp
            _add_source(host, "upnp")
            if upnp.friendly_name and not host.hostname:
                host.hostname = upnp.friendly_name

    if 445 in open_ports:
        smb = smb_probe(host.ip, timeout=timeout)
        if smb and (smb.computer_name or smb.dns_computer):
            host.signals["smb"] = smb
            _add_source(host, "smb")
            if not host.hostname:
                host.hostname = smb.computer_name or smb.dns_computer

    http_ports = [p for p in (80, 8080, 8000, 8443, 443, 8888) if p in open_ports]
    for port in http_ports:
        info = http_probe(host.ip, port, timeout=timeout)
        if info and (info.server or info.title or info.patterns):
            host.signals.setdefault("http", []).append(info)
            _add_source(host, "http_banner")
            if not host.hostname and info.title:
                host.hostname = info.title
            # Login page on a device known to ship with default credentials.
            if (info.has_login_form
                    and any(p in _WEAK_CREDS_DEVICES for p in info.patterns)
                    and "WEAK_CREDS_HINT" not in host.risk_flags):
                host.risk_flags.append("WEAK_CREDS_HINT")


def _add_source(host: Host, source: str) -> None:
    if source not in host.fingerprint_sources:
        host.fingerprint_sources.append(source)
