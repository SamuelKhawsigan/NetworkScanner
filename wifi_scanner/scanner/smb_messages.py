"""Minimal SMB2 request builders (NEGOTIATE + SESSION_SETUP).

Just enough of SMB2 to trigger an NTLMSSP CHALLENGE so we can read a host's
computer/domain names from the target-info. No signing, no real auth.
"""

from __future__ import annotations

import struct


def _smb2_header(command: int, message_id: int, credit_request: int = 1) -> bytes:
    return struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",      # ProtocolId
        64,              # StructureSize
        0,               # CreditCharge
        0,               # Status
        command,         # Command
        credit_request,  # CreditRequest
        0,               # Flags
        0,               # NextCommand
        message_id,      # MessageId
        0,               # Reserved
        0,               # TreeId
        0,               # SessionId
        b"\x00" * 16,    # Signature
    )


def _negotiate_body() -> bytes:
    fixed = struct.pack(
        "<HHHHI16sQ",
        36,            # StructureSize
        2,             # DialectCount
        1,             # SecurityMode (signing enabled)
        0,             # Reserved
        0,             # Capabilities
        b"\x00" * 16,  # ClientGuid
        0,             # ClientStartTime
    )
    dialects = struct.pack("<HH", 0x0202, 0x0210)   # SMB 2.0.2, 2.1
    return fixed + dialects


SMB2_NEGOTIATE = _smb2_header(0, 0) + _negotiate_body()


def smb2_session_setup(security_blob: bytes, message_id: int = 1) -> bytes:
    """SESSION_SETUP carrying an NTLMSSP NEGOTIATE security blob."""
    header = _smb2_header(1, message_id)
    security_offset = 64 + 24                        # header + fixed body
    body = struct.pack(
        "<HBBIIHHQ",
        25,                  # StructureSize
        0,                   # Flags
        1,                   # SecurityMode
        0,                   # Capabilities
        0,                   # Channel
        security_offset,     # SecurityBufferOffset
        len(security_blob),  # SecurityBufferLength
        0,                   # PreviousSessionId
    )
    return header + body + security_blob
