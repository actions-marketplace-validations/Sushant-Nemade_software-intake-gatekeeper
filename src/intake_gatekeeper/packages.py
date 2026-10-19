"""Python distribution metadata and Maven coordinates inside Java archives."""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field
from typing import IO

_PEP503 = re.compile(r"[-_.]+")
_PY_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,200}[A-Za-z0-9])?$")
_PY_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+!_-]{0,127}$")
_MAVEN_PART = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,255}$")
_POM = re.compile(r"^META-INF/maven/[^/]+/[^/]+/pom\.properties$")
_NESTED = (".jar", ".war", ".ear")
MAX_METADATA_HEAD = 256 * 1024
_MAX_POM = 64 * 1024
_MAX_ENTRIES = 200_000


def canonical_python_name(name: str) -> str:
    return _PEP503.sub("-", name).lower()


def parse_python_metadata(data: bytes) -> tuple[str, str] | None:
    """Name and version from core metadata headers (METADATA or PKG-INFO)."""
    headers: dict[str, str] = {}
    for raw in data.decode("utf-8", errors="replace").splitlines():
        if not raw.strip():
            break
        key, separator, value = raw.partition(":")
        if separator and not raw[0].isspace():
            headers.setdefault(key.strip().lower(), value.strip())
    name, version = headers.get("name"), headers.get("version")
    if not name or not version or not _PY_NAME.fullmatch(name) or not _PY_VERSION.fullmatch(version):
        return None
    return canonical_python_name(name), version


@dataclass(frozen=True)
class MavenArtifact:
    group: str
    artifact: str
    version: str
    path: str


@dataclass
class JarResult:
    artifacts: list[MavenArtifact] = field(default_factory=list)
    unidentified: list[str] = field(default_factory=list)
    # (path, message, blocking): blocking problems mean content was not inspected.
    problems: list[tuple[str, str, bool]] = field(default_factory=list)
    entries: int = 0


def parse_pom_properties(data: bytes) -> tuple[str, str, str] | None:
    values: dict[str, str] = {}
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    group, artifact, version = values.get("groupId"), values.get("artifactId"), values.get("version")
    if not group or not artifact or not version:
        return None
    if not all(_MAVEN_PART.fullmatch(part) for part in (group, artifact, version)):
        return None
    return group, artifact, version


def read_java_archive(
    stream: IO[bytes],
    display: str,
    max_nested_bytes: int,
    depth: int = 0,
    result: JarResult | None = None,
) -> JarResult:
    """Collect pom.properties coordinates, descending into nested archives up to two levels."""
    result = result if result is not None else JarResult()
    try:
        archive = zipfile.ZipFile(stream)
    except (zipfile.BadZipFile, ValueError, OSError) as error:
        result.problems.append((display, f"not a readable ZIP archive: {error}", True))
        return result
    found = False
    with archive:
        members = archive.infolist()
        if result.entries + len(members) > _MAX_ENTRIES:
            result.problems.append((display, f"more than {_MAX_ENTRIES} archive entries; stopped", True))
            return result
        result.entries += len(members)
        for member in members:
            inner = f"{display}!/{member.filename}"
            if _POM.fullmatch(member.filename):
                if member.file_size > _MAX_POM:
                    result.problems.append((inner, "pom.properties is larger than 64 KiB", True))
                    continue
                try:
                    with archive.open(member) as handle:
                        coordinates = parse_pom_properties(handle.read(_MAX_POM + 1)[:_MAX_POM])
                except (zipfile.BadZipFile, OSError, NotImplementedError, RuntimeError) as error:
                    result.problems.append((inner, f"entry could not be read: {error}", True))
                    continue
                if coordinates is None:
                    result.problems.append(
                        (inner, "pom.properties lacks groupId, artifactId or version", False)
                    )
                    continue
                found = True
                result.artifacts.append(MavenArtifact(*coordinates, inner))
            elif member.filename.lower().endswith(_NESTED) and not member.is_dir():
                if depth >= 2:
                    result.problems.append(
                        (inner, "nested archive deeper than two levels; not inspected", True)
                    )
                elif member.file_size > max_nested_bytes:
                    result.problems.append(
                        (inner, "nested archive exceeds the size limit; not inspected", True)
                    )
                else:
                    try:
                        with archive.open(member) as handle:
                            blob = handle.read(max_nested_bytes + 1)
                    except (zipfile.BadZipFile, OSError, NotImplementedError, RuntimeError) as error:
                        result.problems.append((inner, f"entry could not be read: {error}", True))
                        continue
                    if len(blob) > max_nested_bytes:
                        result.problems.append(
                            (inner, "nested archive exceeds the size limit; not inspected", True)
                        )
                        continue
                    read_java_archive(io.BytesIO(blob), inner, max_nested_bytes, depth + 1, result)
    if not found and display.lower().endswith(".jar"):
        result.unidentified.append(display)
    return result
