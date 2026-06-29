"""Fingerprint engine — turn raw prober signals into weighted evidence.

Each piece of evidence carries a source, a confidence weight, and any of the
fields it supports (category / subcategory / os / vendor / model). The
classifier and scoring stages consume this evidence list. Evidence comes from
two places: data-driven `signatures.json` matches and a handful of structural
heuristics (open-port profiles, mDNS service types, UPnP device types, OUI
vendor → category, TTL → OS).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .. import config
from .models import Host

# Source -> evidence weight (reuses the tunable weights in config).
SRC_WEIGHT = {
    "snmp_sysdescr": config.SIGNAL_WEIGHTS["snmp_sysdescr"],
    "upnp": config.SIGNAL_WEIGHTS["upnp"],
    "mdns": config.SIGNAL_WEIGHTS["mdns"],
    "smb": config.SIGNAL_WEIGHTS["smb"],
    "netbios": config.SIGNAL_WEIGHTS["netbios"],
    "http": config.SIGNAL_WEIGHTS["http_body"],
    "banner": config.SIGNAL_WEIGHTS["ssh_banner"],
    "vendor": config.SIGNAL_WEIGHTS["oui"],
    "port_profile": config.SIGNAL_WEIGHTS["port_profile"],
    "ttl": config.SIGNAL_WEIGHTS["ttl"],
}


@dataclass
class Evidence:
    source: str
    weight: int
    category: str | None = None
    subcategory: str | None = None
    os: str | None = None
    vendor: str | None = None
    model: str | None = None
    detail: str = ""


# --------------------------------------------------------------------------- #
# Structural heuristic tables
# --------------------------------------------------------------------------- #
PORT_CATEGORY = {
    9100: "Printer", 515: "Printer", 631: "Printer",
    554: "Camera", 37777: "Camera",
    1883: "IoT", 5683: "IoT",
}

# Note: _airplay/_raop are intentionally NOT mapped to Smart TV here — Macs
# advertise them as AirPlay receivers too. Genuine Apple TVs are caught by the
# signature DB, and Mac computers are reclassified in _apple_mac_evidence().
MDNS_CATEGORY = [
    ("_ipp", "Printer"), ("_printer", "Printer"), ("_pdl-datastream", "Printer"),
    ("_googlecast", "Smart TV"), ("_spotify-connect", "Smart TV"),
    ("_sonos", "IoT"), ("_homekit", "IoT"), ("_hap", "IoT"),
]

VENDOR_CATEGORY = [
    ("hikvision", "Camera"), ("dahua", "Camera"), ("axis commun", "Camera"),
    ("hewlett", "Printer"), ("brother", "Printer"), ("canon", "Printer"),
    ("epson", "Printer"), ("lexmark", "Printer"), ("zebra", "Printer"),
    ("synology", "NAS"), ("qnap", "NAS"),
    ("ubiquiti", "Access Point"),
    ("routerboard", "Router"), ("mikrotik", "Router"),
    ("sonos", "IoT"), ("espressif", "IoT"), ("tuya", "IoT"), ("amazon", "IoT"),
    ("apple", "Mobile"),
]


# --------------------------------------------------------------------------- #
# Signature loading
# --------------------------------------------------------------------------- #
_SIG_CACHE: list[dict] | None = None


def load_signatures(path=config.SIGNATURES_PATH, use_cache: bool = True) -> list[dict]:
    """Load device signatures from JSON (cached). Missing file -> empty list."""
    global _SIG_CACHE
    if use_cache and _SIG_CACHE is not None:
        return _SIG_CACHE
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle).get("signatures", [])
    except (OSError, ValueError):
        data = []
    if use_cache:
        _SIG_CACHE = data
    return data


# --------------------------------------------------------------------------- #
# Evidence gathering
# --------------------------------------------------------------------------- #
def _host_texts(host: Host) -> dict[str, str]:
    """Collect the searchable text per signal source for a host."""
    texts: dict[str, str] = {}

    snmp = host.signals.get("snmp")
    texts["snmp_sysdescr"] = " ".join(
        filter(None, [getattr(snmp, "sys_descr", None), getattr(snmp, "sys_name", None)])
    ) if snmp else ""

    https = host.signals.get("http") or []
    texts["http"] = " ".join(
        " ".join(filter(None, [h.server, h.title, " ".join(h.patterns)])) for h in https
    )

    upnp = host.signals.get("upnp")
    texts["upnp"] = " ".join(filter(None, [
        getattr(upnp, "manufacturer", None), getattr(upnp, "model_name", None),
        getattr(upnp, "device_type", None), getattr(upnp, "friendly_name", None),
    ])) if upnp else ""

    mdns = host.signals.get("mdns")
    texts["mdns"] = " ".join(mdns.services) if mdns else ""

    smb = host.signals.get("smb")
    texts["smb"] = " ".join(filter(None, [
        getattr(smb, "computer_name", None), getattr(smb, "domain", None),
        getattr(smb, "dns_domain", None),
    ])) if smb else ""

    nb = host.signals.get("netbios")
    texts["netbios"] = " ".join(filter(None, [
        getattr(nb, "name", None), getattr(nb, "workgroup", None),
    ])) if nb else ""

    texts["vendor"] = host.vendor or ""
    texts["banner"] = " ".join(host.services.values())
    return texts


def _match_signature(sig: dict, texts: dict[str, str]) -> list[str]:
    """Return the source keys whose needle(s) matched for this signature."""
    matched = []
    for src, needle in sig.get("match", {}).items():
        haystack = texts.get(src, "").lower()
        if not haystack:
            continue
        needles = needle if isinstance(needle, list) else [needle]
        if any(n and n.lower() in haystack for n in needles):
            matched.append(src)
    return matched


def _heuristic_evidence(host: Host) -> list[Evidence]:
    evidence: list[Evidence] = []
    ports = set(host.open_ports)

    for port, category in PORT_CATEGORY.items():
        if port in ports:
            evidence.append(Evidence("port_profile", SRC_WEIGHT["port_profile"],
                                     category=category, detail=f"port {port}"))
    if 445 in ports and 548 in ports:
        evidence.append(Evidence("port_profile", SRC_WEIGHT["port_profile"],
                                 category="NAS", detail="smb+afp"))
    # Windows workstation: SMB/NetBIOS identity or the classic 445(+139/3389)
    # client surface. Weight follows the strongest available signal so a named
    # Windows box scores like a real identification, not a lone port hint.
    has_smb = "smb" in host.signals
    has_nb = "netbios" in host.signals
    if 445 in ports or 3389 in ports or has_smb or has_nb:
        if has_smb:
            source, weight = "smb", SRC_WEIGHT["smb"]
        elif has_nb:
            source, weight = "netbios", SRC_WEIGHT["netbios"]
        else:
            source, weight = "port_profile", SRC_WEIGHT["port_profile"]
        evidence.append(Evidence(source, weight, category="Workstation",
                                 subcategory="Windows Workstation", os="Windows",
                                 detail="windows client"))

    mdns = host.signals.get("mdns")
    if mdns:
        joined = " ".join(mdns.services).lower()
        for needle, category in MDNS_CATEGORY:
            if needle in joined:
                evidence.append(Evidence("mdns", SRC_WEIGHT["mdns"],
                                         category=category, detail=needle))

    upnp = host.signals.get("upnp")
    if upnp and upnp.device_type:
        dt = upnp.device_type.lower()
        category = None
        if "internetgateway" in dt or "wandevice" in dt:
            category = "Router"
        elif "mediarenderer" in dt or "mediaserver" in dt:
            category = "Smart TV"
        elif "printer" in dt:
            category = "Printer"
        if category:
            evidence.append(Evidence("upnp", SRC_WEIGHT["upnp"], category=category,
                                     vendor=upnp.manufacturer, model=upnp.model_name))

    vendor_l = (host.vendor or "").lower()
    for needle, category in VENDOR_CATEGORY:
        if needle in vendor_l:
            evidence.append(Evidence("vendor", SRC_WEIGHT["vendor"], category=category))
            break

    if host.ttl in config.TTL_OS_HINTS:
        evidence.append(Evidence("ttl", SRC_WEIGHT["ttl"], os=config.TTL_OS_HINTS[host.ttl]))

    return evidence


def _apple_mac_evidence(host: Host) -> Evidence | None:
    """Detect Apple *computers* (vs Apple TVs) so AirPlay doesn't make them TVs.

    Returns strong Laptop/Workstation evidence when the hostname (or Apple
    vendor + generic Mac name) identifies a Mac; otherwise None.
    """
    host_l = (host.hostname or "").lower()
    is_apple = "apple" in (host.vendor or "").lower()

    if any(k in host_l for k in ("macbook", "mbp", "macair")):
        kind = ("Laptop", "MacBook (macOS)")
    elif any(k in host_l for k in ("imac", "mac mini", "macmini",
                                   "mac pro", "macpro", "mac studio")):
        kind = ("Workstation", "Mac (macOS)")
    elif is_apple and (host_l.startswith("mac-") or host_l == "mac"):
        kind = ("Laptop", "Mac (macOS)")
    else:
        return None

    return Evidence("mdns", SRC_WEIGHT["mdns"] + 2, category=kind[0],
                    subcategory=kind[1], os="macOS", vendor="Apple",
                    detail="apple computer")


def gather_evidence(host: Host, signatures: list[dict] | None = None) -> list[Evidence]:
    """Produce the full weighted evidence list for a host."""
    signatures = signatures if signatures is not None else load_signatures()
    texts = _host_texts(host)
    evidence: list[Evidence] = []

    for sig in signatures:
        matched = _match_signature(sig, texts)
        if matched:
            weight = max(SRC_WEIGHT.get(src, 5) for src in matched)
            evidence.append(Evidence(
                source="+".join(sorted(set(matched))),
                weight=weight,
                category=sig.get("category"),
                subcategory=sig.get("subcategory"),
                os=sig.get("os"),
                vendor=sig.get("vendor"),
                model=sig.get("model"),
                detail=sig.get("name", ""),
            ))

    evidence.extend(_heuristic_evidence(host))

    # An Apple computer overrides any Smart TV evidence its AirPlay services
    # would otherwise produce (e.g. a MacBook advertising _airplay/_raop).
    mac_ev = _apple_mac_evidence(host)
    if mac_ev:
        evidence = [e for e in evidence if e.category != "Smart TV"]
        evidence.append(mac_ev)
    return evidence


def best_field(evidence: list[Evidence], attr: str) -> str | None:
    """Highest-weight non-empty value of `attr` across the evidence."""
    best, best_weight = None, -1
    for ev in evidence:
        value = getattr(ev, attr)
        if value and ev.weight > best_weight:
            best, best_weight = value, ev.weight
    return best
