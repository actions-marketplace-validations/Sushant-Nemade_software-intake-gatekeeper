"""Read the Authenticode signer identity from a PE file without verifying it.

Only identifies who the embedded signature claims to be from. Cryptographic validity, chain trust,
revocation and catalog signatures are outside this module.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from intake_gatekeeper import objfile
from intake_gatekeeper.golang import Bytes

_MAX_TABLE = 16 * 1024 * 1024
_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")
_OID_CN = bytes.fromhex("550403")
_OID_O = bytes.fromhex("55040a")
_STRING_TAGS = {
    0x0C: "utf-8",
    0x13: "ascii",
    0x16: "ascii",
    0x14: "latin-1",
    0x1E: "utf-16-be",
    0x1C: "utf-32-be",
}


@dataclass(frozen=True)
class Signer:
    subject: str
    issuer: str
    serial: str
    sha1: str
    sha256: str


class SignatureError(ValueError):
    pass


def _tlv(data: bytes, pos: int, end: int) -> tuple[int, int, int]:
    """Return (tag, content start, content end) of the DER element at pos."""
    if pos + 2 > end:
        raise SignatureError("truncated DER element")
    tag, first = data[pos], data[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or pos + count > end:
            raise SignatureError("unsupported DER length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    if pos + length > end:
        raise SignatureError("DER element exceeds its container")
    return tag, pos, pos + length


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int, int]]:
    """(tag, content start, content end, element start) for each element in a range."""
    items = []
    while start < end:
        tag, inner, stop = _tlv(data, start, end)
        items.append((tag, inner, stop, start))
        start = stop
    return items


def _name(data: bytes, start: int, end: int) -> str:
    parts: dict[bytes, str] = {}
    for _set_tag, set_start, set_end, _ in _children(data, start, end):
        for _seq_tag, seq_start, seq_end, _ in _children(data, set_start, set_end):
            items = _children(data, seq_start, seq_end)
            if len(items) != 2 or items[0][0] != 0x06:
                continue
            oid = data[items[0][1] : items[0][2]]
            tag, value_start, value_end, _ = items[1]
            encoding = _STRING_TAGS.get(tag)
            if oid in (_OID_CN, _OID_O) and encoding and oid not in parts:
                parts[oid] = data[value_start:value_end].decode(encoding, errors="replace")
    labels = [f"CN={parts[_OID_CN]}"] if _OID_CN in parts else []
    if _OID_O in parts:
        labels.append(f"O={parts[_OID_O]}")
    return ", ".join(labels) or "(no CN or O)"


def _certificate(data: bytes, start: int, end: int) -> tuple[bytes, bytes, bytes]:
    """Return (serial, issuer name, subject name) contents of one certificate."""
    _tag, tbs_start, tbs_end, _ = _children(data, start, end)[0]
    fields = _children(data, tbs_start, tbs_end)
    if fields and fields[0][0] == 0xA0:
        fields = fields[1:]
    if len(fields) < 5:
        raise SignatureError("certificate is missing fields")
    serial = data[fields[0][1] : fields[0][2]]
    issuer = data[fields[2][1] : fields[2][2]]
    subject = data[fields[4][1] : fields[4][2]]
    return serial, issuer, subject


def parse_pkcs7(blob: bytes) -> Signer:
    _tag, info_start, info_end = _tlv(blob, 0, len(blob))
    info = _children(blob, info_start, info_end)
    if len(info) < 2 or blob[info[0][1] : info[0][2]] != _SIGNED_DATA or info[1][0] != 0xA0:
        raise SignatureError("not a PKCS#7 SignedData structure")
    _tag, signed_start, signed_end, _ = _children(blob, info[1][1], info[1][2])[0]
    parts = _children(blob, signed_start, signed_end)
    certificates = next((p for p in parts if p[0] == 0xA0), None)
    signer_infos = parts[-1]
    if certificates is None or signer_infos[0] != 0x31:
        raise SignatureError("SignedData has no certificates or signer")
    signer_info = _children(blob, signer_infos[1], signer_infos[2])[0]
    sid = _children(blob, signer_info[1], signer_info[2])[1]
    if sid[0] != 0x30:
        raise SignatureError("signer identified by key id, not issuer and serial")
    issuer_tlv, serial_tlv = _children(blob, sid[1], sid[2])[:2]
    wanted_issuer = blob[issuer_tlv[1] : issuer_tlv[2]]
    wanted_serial = blob[serial_tlv[1] : serial_tlv[2]]
    for _tag, cert_start, cert_end, cert_begin in _children(blob, certificates[1], certificates[2]):
        serial, issuer, subject = _certificate(blob, cert_start, cert_end)
        if serial == wanted_serial and issuer == wanted_issuer:
            der = blob[cert_begin:cert_end]
            return Signer(
                subject=_name(subject, 0, len(subject)),
                issuer=_name(issuer, 0, len(issuer)),
                serial=serial.lstrip(b"\x00").hex().upper() or "00",
                sha1=hashlib.sha1(der, usedforsecurity=False).hexdigest().upper(),
                sha256=hashlib.sha256(der).hexdigest(),
            )
    raise SignatureError("signer certificate is not included in the signature")


def read_signer(data: Bytes) -> Signer | None:
    """Signer of the first embedded Authenticode signature; None when the file has none."""
    try:
        table = objfile.pe_certificate_table(data)
    except objfile.FormatError as error:
        raise SignatureError(f"PE headers are malformed: {error}") from None
    if table is None:
        return None
    if table.size > _MAX_TABLE or table.size < 8:
        raise SignatureError("certificate table size is out of range")
    length, _revision, kind = struct.unpack("<IHH", data[table.offset : table.offset + 8])
    if kind != 0x0002 or not 8 < length <= table.size:
        raise SignatureError("certificate table holds no PKCS#7 signature")
    return parse_pkcs7(bytes(data[table.offset + 8 : table.offset + length]))
