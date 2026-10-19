"""Minimal, valid ELF64, PE32+ and Mach-O 64 files with one named section, for parser tests."""

from __future__ import annotations

import struct


def elf(section: str, payload: bytes, big_endian: bool = False) -> bytes:
    order = ">" if big_endian else "<"
    names = b"\x00" + section.encode() + b"\x00.shstrtab\x00"
    data_offset = 64
    names_offset = data_offset + len(payload)
    shoff = (names_offset + len(names) + 7) & ~7
    ident = b"\x7fELF" + bytes([2, 2 if big_endian else 1, 1]) + bytes(9)
    header = ident + struct.pack(order + "HHIQQQIHHHHHH", 2, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 3, 2)

    def shdr(name: int, kind: int, offset: int, size: int) -> bytes:
        return struct.pack(order + "IIQQQQIIQQ", name, kind, 0, 0, offset, size, 0, 0, 1, 0)

    body = header + payload + names
    body += bytes(shoff - len(body))
    return (
        body
        + shdr(0, 0, 0, 0)
        + shdr(1, 1, data_offset, len(payload))
        + shdr(2 + len(section), 3, names_offset, len(names))
    )


def pe(section: str | None = None, payload: bytes = b"", certificate: bytes | None = None) -> bytes:
    sections = 1 if section else 0
    optional = bytearray(240)
    optional[0:2] = struct.pack("<H", 0x20B)
    optional[108:112] = struct.pack("<I", 16)
    headers = 0x40 + 24 + len(optional) + 40 * sections
    data_offset = (headers + 0x1FF) & ~0x1FF
    image = bytearray(data_offset)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = struct.pack("<I", 0x40)
    image[0x40:0x44] = b"PE\x00\x00"
    image[0x44:0x58] = struct.pack("<HHIIIHH", 0x8664, sections, 0, 0, 0, len(optional), 0x22)
    if section:
        raw = (len(payload) + 0x1FF) & ~0x1FF
        entry = struct.pack("<8sIIII", section.encode(), len(payload), 0x1000, raw, data_offset) + bytes(16)
        start = 0x58 + len(optional)
        image[start : start + 40] = entry
        image += payload + bytes(raw - len(payload))
    if certificate is not None:
        table_offset = len(image)
        blob = struct.pack("<IHH", 8 + len(certificate), 0x0200, 0x0002) + certificate
        blob += bytes(-len(blob) % 8)
        image += blob
        optional[112 + 4 * 8 : 112 + 5 * 8] = struct.pack("<II", table_offset, len(blob))
    image[0x58 : 0x58 + len(optional)] = optional
    return bytes(image)


def macho(section: str, payload: bytes, segment: str = "__DATA", fat: bool = False) -> bytes:
    commands = 72 + 80
    data_offset = 32 + commands
    segment_cmd = struct.pack(
        "<II16sQQQQIIII",
        0x19,
        commands,
        segment.encode(),
        0,
        len(payload),
        data_offset,
        len(payload),
        3,
        3,
        1,
        0,
    )
    section_hdr = struct.pack(
        "<16s16sQQIIIIIIII",
        section.encode(),
        segment.encode(),
        0,
        len(payload),
        data_offset,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    thin = (
        struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, commands, 0, 0) + segment_cmd + section_hdr
    )
    thin += payload
    if not fat:
        return thin
    offset = 4096
    header = struct.pack(">II", 0xCAFEBABE, 1) + struct.pack(">IIIII", 0x0100000C, 0, offset, len(thin), 12)
    return header + bytes(offset - len(header)) + thin
