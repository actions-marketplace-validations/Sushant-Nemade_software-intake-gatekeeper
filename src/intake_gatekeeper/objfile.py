"""Bounded, read-only section lookup for ELF, PE and Mach-O files (untrusted input)."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from intake_gatekeeper.golang import Bytes

_MAX_SECTIONS = 4096
_MAX_LOAD_COMMANDS = 4096
_MAX_FAT_ARCHES = 30


@dataclass(frozen=True)
class Section:
    offset: int
    size: int


class FormatError(ValueError):
    pass


def _unpack(fmt: str, data: Bytes, offset: int) -> tuple[Any, ...]:
    end = offset + struct.calcsize(fmt)
    if offset < 0 or end > len(data):
        raise FormatError("header points outside the file")
    return struct.unpack(fmt, data[offset:end])


def _checked(data: Bytes, offset: int, size: int) -> Section:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise FormatError("section points outside the file")
    return Section(offset, size)


def _elf(data: Bytes, name: str) -> Section | None:
    is64 = data[4] == 2
    order = "<" if data[5] == 1 else ">"
    if is64:
        (shoff,) = _unpack(order + "Q", data, 0x28)
        shentsize, shnum, shstrndx = _unpack(order + "HHH", data, 0x3A)
        header = order + "IIQQQQ"
    else:
        (shoff,) = _unpack(order + "I", data, 0x20)
        shentsize, shnum, shstrndx = _unpack(order + "HHH", data, 0x2E)
        header = order + "IIIIII"
    if shoff == 0 or shnum == 0 or shnum > _MAX_SECTIONS or shentsize < struct.calcsize(header):
        return None
    if shstrndx >= shnum:
        raise FormatError("invalid section name table index")
    sections = [_unpack(header, data, shoff + index * shentsize) for index in range(shnum)]
    strtab = sections[shstrndx]
    strtab_offset, strtab_size = strtab[4], strtab[5]
    _checked(data, strtab_offset, strtab_size)
    wanted = name.encode()
    for name_offset, kind, _flags, _addr, offset, size in sections:
        if kind == 8 or name_offset >= strtab_size:  # SHT_NOBITS has no file data
            continue
        start = strtab_offset + name_offset
        end = data.find(b"\x00", start, strtab_offset + strtab_size)
        if end >= 0 and data[start:end] == wanted:
            return _checked(data, offset, size)
    return None


def _pe_header(data: Bytes) -> tuple[int, int, int, int] | None:
    """(coff offset, sections, optional header offset, optional header size); None if not PE."""
    if len(data) < 0x40:
        return None
    (pe,) = _unpack("<I", data, 0x3C)
    if pe + 24 > len(data) or data[pe : pe + 4] != b"PE\x00\x00":
        return None  # a DOS executable or another MZ-prefixed file, not a PE image
    (sections,) = _unpack("<H", data, pe + 6)
    (optional_size,) = _unpack("<H", data, pe + 20)
    return pe + 4, sections, pe + 24, optional_size


def _pe(data: Bytes, name: str) -> Section | None:
    header = _pe_header(data)
    if header is None:
        return None
    _coff, count, optional, optional_size = header
    if count > _MAX_SECTIONS:
        raise FormatError("too many PE sections")
    table = optional + optional_size
    wanted = name.encode()
    for index in range(count):
        raw_name, virtual_size, _rva, raw_size, raw_offset = _unpack("<8sIIII", data, table + index * 40)
        if raw_name.rstrip(b"\x00") == wanted and raw_offset:
            size = min(virtual_size, raw_size) if virtual_size else raw_size
            return _checked(data, raw_offset, size)
    return None


def pe_certificate_table(data: Bytes) -> Section | None:
    """The Authenticode certificate table (data directory 4), whose offset is a file offset."""
    header = _pe_header(data)
    if header is None:
        return None
    _coff, _count, optional, optional_size = header
    (magic,) = _unpack("<H", data, optional)
    directories = {0x10B: 96, 0x20B: 112}.get(magic)
    if directories is None:
        raise FormatError("unknown PE optional header")
    if optional_size < directories:
        return None
    (entries,) = _unpack("<I", data, optional + directories - 4)
    if entries <= 4 or optional_size < directories + 5 * 8:
        return None
    offset, size = _unpack("<II", data, optional + directories + 4 * 8)
    return _checked(data, offset, size) if offset and size else None


def _macho(data: Bytes, base: int, segment: str, name: str) -> Section | None:
    magic = bytes(data[base : base + 4])
    order = "<" if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else ">"
    is64 = magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
    (ncmds,) = _unpack(order + "I", data, base + 16)
    if ncmds > _MAX_LOAD_COMMANDS:
        raise FormatError("too many Mach-O load commands")
    position = base + (32 if is64 else 28)
    segment_cmd, segment_fmt, section_fmt = (
        (0x19, order + "16sQQQQIIII", order + "16s16sQQI")
        if is64
        else (0x1, order + "16sIIIIIIII", order + "16s16sIII")
    )
    segment_size = struct.calcsize(segment_fmt)
    section_size = 80 if is64 else 68
    for _ in range(ncmds):
        cmd, cmdsize = _unpack(order + "II", data, position)
        if cmdsize < 8:
            raise FormatError("invalid Mach-O load command size")
        if cmd == segment_cmd:
            fields = _unpack(segment_fmt, data, position + 8)
            nsects = fields[-2]
            if nsects > _MAX_SECTIONS:
                raise FormatError("too many Mach-O sections")
            first = position + 8 + segment_size
            for index in range(nsects):
                sectname, segname, _addr, size, offset = _unpack(
                    section_fmt, data, first + index * section_size
                )
                if sectname.rstrip(b"\x00") == name.encode() and segname.rstrip(b"\x00") == segment.encode():
                    return _checked(data, base + offset, size)
        position += cmdsize
    return None


def find_section(data: Bytes, name: str, macho_segment: str = "__DATA") -> Section | None:
    """Locate a named section; None when absent. Raises FormatError for malformed headers."""
    head = bytes(data[:4])
    if head == b"\x7fELF":
        return _elf(data, name)
    if head[:2] == b"MZ":
        return _pe(data, name)
    if head in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        return _macho(data, 0, macho_segment, name)
    if head == b"\xca\xfe\xba\xbe":
        (count,) = _unpack(">I", data, 4)
        if count > _MAX_FAT_ARCHES:  # also rules out Java class files, which share this magic
            return None
        for index in range(count):
            _cpu, _sub, offset, _size, _align = _unpack(">IIIII", data, 8 + index * 20)
            found = _macho(data, offset, macho_segment, name)
            if found is not None:
                return found
    return None
