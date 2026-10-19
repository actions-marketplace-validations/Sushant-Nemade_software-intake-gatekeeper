"""Decode the dependency list that `cargo auditable` embeds in Rust executables (.dep-v0 section)."""

from __future__ import annotations

import json
import re
import zlib
from dataclasses import dataclass

from intake_gatekeeper import objfile
from intake_gatekeeper.golang import Bytes

SECTION = ".dep-v0"
_MAX_COMPRESSED = 4 * 1024 * 1024
_MAX_JSON = 8 * 1024 * 1024
_MAX_PACKAGES = 50_000
_CRATE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_CRATES_IO = {"crates.io", "CratesIo"}


@dataclass(frozen=True)
class Crate:
    name: str
    version: str
    source: str
    build_only: bool
    root: bool

    @property
    def from_crates_io(self) -> bool:
        return self.source in _CRATES_IO


class AuditDataError(ValueError):
    pass


def _source(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("Other"), str):
        return f"other:{value['Other']}"
    raise AuditDataError("package source has an unexpected type")


def parse_audit_json(text: bytes) -> list[Crate]:
    try:
        document = json.loads(text.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditDataError(f"audit data is not valid JSON: {error}") from None
    packages = document.get("packages") if isinstance(document, dict) else None
    if not isinstance(packages, list):
        raise AuditDataError("audit data has no 'packages' array")
    if len(packages) > _MAX_PACKAGES:
        raise AuditDataError("audit data lists too many packages")
    crates: list[Crate] = []
    for package in packages:
        if not isinstance(package, dict):
            raise AuditDataError("package entry is not an object")
        name, version = package.get("name"), package.get("version")
        if not isinstance(name, str) or not _CRATE.fullmatch(name):
            raise AuditDataError("package name is missing or malformed")
        if not isinstance(version, str) or not _SEMVER.fullmatch(version):
            raise AuditDataError(f"version of {name} is missing or not semver")
        kind = package.get("kind", "runtime")
        if kind not in ("runtime", "build"):
            raise AuditDataError(f"unknown dependency kind {kind!r}")
        crates.append(
            Crate(name, version, _source(package.get("source")), kind == "build", package.get("root") is True)
        )
    return crates


def read_audit_data(data: Bytes) -> list[Crate] | None:
    """Crates from a `cargo auditable` binary; None when the section is absent."""
    try:
        section = objfile.find_section(data, SECTION)
    except objfile.FormatError as error:
        raise AuditDataError(f"object headers are malformed: {error}") from None
    if section is None:
        return None
    if section.size > _MAX_COMPRESSED:
        raise AuditDataError("audit data section is larger than 4 MiB")
    decompressor = zlib.decompressobj()
    try:
        text = decompressor.decompress(data[section.offset : section.offset + section.size], _MAX_JSON + 1)
    except zlib.error as error:
        raise AuditDataError(f"audit data is not zlib-compressed: {error}") from None
    if len(text) > _MAX_JSON or decompressor.unconsumed_tail:
        raise AuditDataError("decompressed audit data exceeds 8 MiB")
    return parse_audit_json(text)
