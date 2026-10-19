"""Walk a target without executing or extracting it and build an inventory with evidence."""

from __future__ import annotations

import hashlib
import json
import mmap
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from intake_gatekeeper import asar, authenticode, electron, golang, packages, rust
from intake_gatekeeper.model import (
    BinaryInfo,
    Component,
    ElectronInfo,
    Finding,
    Gap,
    GatekeeperError,
    Inventory,
    Location,
)
from intake_gatekeeper.rules import RULES

_BINARY_MAGICS = (
    b"MZ",
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
)
_JS_SUFFIXES = (".js", ".cjs", ".mjs", ".ts", ".cts", ".mts")
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][\w.~-]*/)?[a-z0-9][\w.~-]*$", re.IGNORECASE)
_VERSION_TEXT = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_~-]{0,127}$")
_NUGET_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,255}$")
_MAX_LOCATIONS = 10
_MAX_FINDINGS = 5000
_MAX_ENDPOINTS = 2000
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


@dataclass(frozen=True)
class Limits:
    max_files: int = 250_000
    max_depth: int = 64
    max_binary_bytes: int = 2 * 1024**3
    max_text_bytes: int = 32 * 1024**2
    max_manifest_bytes: int = 8 * 1024**2
    max_asar_header_bytes: int = 64 * 1024**2
    max_nested_archive_bytes: int = 64 * 1024**2


class _Collector:
    def __init__(self) -> None:
        self.inventory = Inventory()
        self._components: dict[tuple[str, str, str], Component] = {}
        self._limited = False

    def component(self, component: Component, location: Location) -> None:
        existing = self._components.get(component.key)
        if existing is None:
            existing = component
            self._components[component.key] = component
            self.inventory.components.append(component)
        existing.occurrences += 1
        if len(existing.locations) < _MAX_LOCATIONS and location not in existing.locations:
            existing.locations.append(location)

    def finding(self, rule_id: str, location: Location, detail: str | None = None) -> None:
        if len(self.inventory.findings) >= _MAX_FINDINGS:
            if not self._limited:
                self._limited = True
                self.gap("finding-limit", f"Stopped recording findings after {_MAX_FINDINGS}.")
            return
        rule = RULES[rule_id]
        message = rule.help if detail is None else f"{detail} {rule.help}"
        self.inventory.findings.append(
            Finding(rule_id, rule.severity, rule.title, message, location=location)
        )

    def gap(self, code: str, message: str, path: str | None = None, blocking: bool = True) -> None:
        self.inventory.gaps.append(Gap(code, message, path, blocking))


def _is_link(entry: os.DirEntry[str]) -> bool:
    if entry.is_symlink():
        return True
    if os.name == "nt":
        attributes = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
        return bool(attributes & _REPARSE_POINT)
    return False


def _parse_json(data: bytes) -> object:
    return json.loads(data.decode("utf-8-sig"))


def _npm_package(parts: tuple[str, ...]) -> bool:
    if len(parts) >= 3 and parts[-3] == "node_modules" and not parts[-2].startswith("@"):
        return True
    return len(parts) >= 4 and parts[-4] == "node_modules" and parts[-3].startswith("@")


def _app_manifest(parts: tuple[str, ...], in_archive: bool) -> bool:
    if "node_modules" in parts:
        return False
    if in_archive:
        return parts == ("package.json",)
    return len(parts) >= 3 and parts[-3:] == ("resources", "app", "package.json")


def _inspect_package_json(
    collector: _Collector, data: bytes, parts: tuple[str, ...], display: str, in_archive: bool
) -> None:
    library = _npm_package(parts)
    application = _app_manifest(parts, in_archive)
    if not library and not application:
        return
    try:
        manifest = _parse_json(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        collector.gap("parse-error", "package.json is not valid JSON.", display)
        return
    if not isinstance(manifest, dict):
        return
    name, version = manifest.get("name"), manifest.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        if library:
            collector.gap("parse-error", "Installed package has no name or version.", display, False)
        return
    if not _NPM_NAME.fullmatch(name) or len(name) > 214 or not _VERSION_TEXT.fullmatch(version):
        collector.gap("parse-error", "Package name or version is not well formed.", display)
        return
    location = Location(display)
    if library:
        collector.component(Component("npm", name, version), location)
    else:
        collector.component(
            Component(
                "npm",
                name,
                version,
                kind="application",
                queryable=False,
                note="Application manifest; identifies the target, not a dependency.",
            ),
            location,
        )


def _inspect_deps_json(collector: _Collector, data: bytes, display: str) -> None:
    try:
        document = _parse_json(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        collector.gap("parse-error", ".deps.json is not valid JSON.", display)
        return
    libraries = document.get("libraries") if isinstance(document, dict) else None
    if not isinstance(libraries, dict):
        collector.gap("parse-error", ".deps.json has no 'libraries' object.", display)
        return
    for key, value in libraries.items():
        if not isinstance(value, dict) or value.get("type") not in ("package", "runtimepack"):
            continue
        name, separator, version = str(key).rpartition("/")
        name = name.removeprefix("runtimepack.")
        if not separator or not _NUGET_NAME.fullmatch(name) or not _VERSION_TEXT.fullmatch(version):
            collector.gap("parse-error", f"Unrecognised library key {key!r}.", display, False)
            continue
        collector.component(Component("NuGet", name, version), Location(display))


def _inspect_runtimeconfig(collector: _Collector, data: bytes, display: str) -> None:
    try:
        document = _parse_json(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        collector.gap("parse-error", ".runtimeconfig.json is not valid JSON.", display)
        return
    options = document.get("runtimeOptions") if isinstance(document, dict) else None
    if not isinstance(options, dict):
        return
    frameworks = options.get("frameworks")
    candidates = frameworks if isinstance(frameworks, list) else [options.get("framework")]
    for framework in candidates:
        if not isinstance(framework, dict):
            continue
        name, version = framework.get("name"), framework.get("version")
        if isinstance(name, str) and isinstance(version, str) and _NUGET_NAME.fullmatch(name):
            collector.component(
                Component(
                    "NuGet",
                    name,
                    version,
                    kind="framework",
                    queryable=False,
                    note="Minimum shared framework version; the host's installed runtime decides "
                    "actual exposure.",
                ),
                Location(display),
            )
            collector.gap(
                "host-runtime",
                f"Framework-dependent .NET app needs {name} >= {version}; patch level of the host "
                "runtime is outside this scan.",
                display,
                blocking=False,
            )


def _inspect_javascript(collector: _Collector, data: bytes, display: str) -> None:
    text = data.decode("utf-8", errors="replace")
    for rule_id, location in electron.scan_javascript(text, display):
        collector.finding(rule_id, location)
    endpoints = collector.inventory.endpoints
    for host in electron.find_endpoints(text):
        if host in endpoints:
            if len(endpoints[host]) < 3 and display not in endpoints[host]:
                endpoints[host].append(display)
        elif len(endpoints) < _MAX_ENDPOINTS:
            endpoints[host] = [display]


def _inspect_binary(collector: _Collector, data: golang.Bytes, display: str) -> None:
    kinds: list[str] = []
    try:
        info = golang.read_buildinfo(data)
    except golang.LegacyGoBinary as error:
        collector.gap("unsupported-format", str(error), display)
        info = None
        kinds.append("go")
    if info is not None:
        _record_go(collector, info, display)
        kinds.append("go")
    try:
        crates = rust.read_audit_data(data)
    except rust.AuditDataError as error:
        collector.gap("parse-error", f"Rust dependency data could not be read: {error}.", display)
        crates = None
    if crates is not None:
        _record_rust(collector, crates, display)
        kinds.append("rust")
    signer: authenticode.Signer | None = None
    if bytes(data[:2]) == b"MZ":
        try:
            signer = authenticode.read_signer(data)
        except authenticode.SignatureError as error:
            collector.gap(
                "signature-unreadable", f"Authenticode signature could not be read: {error}.", display
            )
    wires = electron.read_fuse_wires(data)
    if wires:
        kinds.append("electron")
    collector.inventory.binaries.append(
        BinaryInfo(
            display,
            len(data),
            hashlib.sha256(data).hexdigest(),
            "+".join(kinds) or "native",
            signer.subject if signer else None,
            signer.issuer if signer else None,
            signer.sha1 if signer else None,
        )
    )
    if not wires:
        return
    versions = electron.find_electron_versions(data)
    version = versions[0] if len(versions) == 1 else None
    if len(versions) != 1:
        collector.gap(
            "electron-version",
            "Electron runtime version could not be determined uniquely "
            f"({', '.join(versions) or 'no version string found'}).",
            display,
        )
    wire = wires[0]
    collector.inventory.electron.append(ElectronInfo(display, version, wire.states))
    if version is not None:
        collector.component(
            Component(
                "npm",
                "electron",
                version,
                kind="framework",
                note="Electron runtime detected from the executable.",
            ),
            Location(display),
        )
    if wire.version != 1:
        collector.gap("unsupported-format", f"Unknown fuse wire version {wire.version}.", display)
        return
    location = Location(display, snippet=f"fuse wire v1 '{wire.raw}' at offset {wire.offset}")
    for fuse, risky, rule_id in electron.FUSE_RULES:
        if wire.states.get(fuse) == risky:
            collector.finding(rule_id, location, f"Fuse {fuse} is {risky}.")


def _record_go(collector: _Collector, info: golang.GoBuildInfo, display: str) -> None:
    location = Location(display, snippet=info.go_version)
    stdlib = golang.stdlib_version(info.go_version)
    collector.component(
        Component(
            "Go",
            "stdlib",
            stdlib or info.go_version,
            kind="framework",
            queryable=stdlib is not None,
            note=None if stdlib else "Toolchain is not a tagged Go release.",
        ),
        location,
    )
    if info.main is not None and info.main.path:
        version = info.main.version
        collector.component(
            Component(
                "Go",
                info.main.path,
                version,
                kind="application",
                queryable=version.startswith("v"),
                note="Main module of the executable.",
            ),
            location,
        )
    for module in info.deps:
        if module.replace_path is not None:
            if not module.replace_version:
                collector.component(
                    Component(
                        "Go",
                        module.path,
                        module.version,
                        queryable=False,
                        note=f"Replaced by local path {module.replace_path}.",
                    ),
                    location,
                )
                continue
            collector.component(
                Component(
                    "Go",
                    module.replace_path,
                    module.replace_version,
                    note=f"Replacement for {module.path} {module.version}.",
                ),
                location,
            )
            continue
        collector.component(Component("Go", module.path, module.version), location)


def _record_rust(collector: _Collector, crates: list[rust.Crate], display: str) -> None:
    location = Location(display, snippet="cargo auditable .dep-v0")
    for crate in crates:
        if crate.root:
            component = Component(
                "crates.io",
                crate.name,
                crate.version,
                kind="application",
                queryable=False,
                note="Root package of the executable.",
            )
        elif crate.build_only:
            component = Component(
                "crates.io",
                crate.name,
                crate.version,
                queryable=False,
                note="Build-time dependency (build script or proc-macro); not linked into the executable.",
            )
        elif not crate.from_crates_io:
            component = Component(
                "crates.io",
                crate.name,
                crate.version,
                queryable=False,
                note=f"Source is {crate.source}, not crates.io; advisories may not apply.",
            )
        else:
            component = Component("crates.io", crate.name, crate.version)
        collector.component(component, location)


def _inspect_python_metadata(collector: _Collector, path: Path, display: str) -> None:
    with path.open("rb") as handle:
        head = handle.read(packages.MAX_METADATA_HEAD)
    parsed = packages.parse_python_metadata(head)
    if parsed is None:
        collector.gap("parse-error", "Python package metadata has no valid Name and Version.", display, False)
        return
    collector.component(Component("PyPI", *parsed), Location(display))


def _inspect_java_archive(collector: _Collector, path: Path, display: str, limits: Limits) -> None:
    with path.open("rb") as handle:
        result = packages.read_java_archive(handle, display, limits.max_nested_archive_bytes)
    collector.inventory.archive_entries_examined += result.entries
    for artifact in result.artifacts:
        collector.component(
            Component("Maven", f"{artifact.group}:{artifact.artifact}", artifact.version),
            Location(artifact.path),
        )
    for problem_path, message, blocking in result.problems:
        collector.gap("archive-entry", message[0].upper() + message[1:] + ".", problem_path, blocking)
    if result.unidentified:
        collector.gap(
            "jar-unidentified",
            f"{len(result.unidentified)} JAR(s) carry no Maven pom.properties, so their libraries are not "
            "inventoried.",
            result.unidentified[0],
            blocking=False,
        )


def _inspect_asar(collector: _Collector, path: Path, display: str, limits: Limits) -> None:
    size = path.stat().st_size
    with path.open("rb") as handle:
        try:
            header, data_start = asar.read_header(handle, size, limits.max_asar_header_bytes)
        except asar.AsarError as error:
            collector.gap("parse-error", str(error), display)
            return
        budget = max(limits.max_files - collector.inventory.files_examined, 0)
        for entry in asar.iter_entries(header, budget):
            if isinstance(entry, str):
                collector.gap("archive-entry", entry, display)
                continue
            collector.inventory.archive_entries_examined += 1
            if entry.unpacked:
                continue
            parts = tuple(PurePosixPath(entry.path).parts)
            inner = f"{display}!/{entry.path}"
            name = parts[-1]
            if name == "package.json":
                limit = limits.max_manifest_bytes
            elif name.endswith(_JS_SUFFIXES) and "node_modules" not in parts:
                limit = limits.max_text_bytes
            else:
                continue
            if entry.size > limit:
                collector.gap("size-limit", f"Skipped entry larger than {limit} bytes.", inner)
                continue
            try:
                data = asar.read_entry(handle, data_start, size, entry)
            except asar.AsarError as error:
                collector.gap("parse-error", str(error), display)
                continue
            if name == "package.json":
                _inspect_package_json(collector, data, parts, inner, in_archive=True)
            else:
                _inspect_javascript(collector, data, inner)


def _read_bounded(path: Path, limit: int) -> bytes | None:
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    return None if len(data) > limit else data


def _inspect_file(
    collector: _Collector, path: Path, parts: tuple[str, ...], display: str, limits: Limits
) -> None:
    name = parts[-1]
    lowered = name.lower()
    size = path.stat().st_size
    if lowered.endswith(".asar"):
        _inspect_asar(collector, path, display, limits)
        return
    if lowered.endswith((".jar", ".war", ".ear")):
        _inspect_java_archive(collector, path, display, limits)
        return
    parent = parts[-2].lower() if len(parts) >= 2 else ""
    if (
        (name == "METADATA" and parent.endswith(".dist-info"))
        or (name == "PKG-INFO" and parent.endswith(".egg-info"))
        or (lowered.endswith(".egg-info") and size > 0)
    ):
        _inspect_python_metadata(collector, path, display)
        return
    manifest = lowered == "package.json" or lowered.endswith((".deps.json", ".runtimeconfig.json"))
    if manifest:
        data = _read_bounded(path, limits.max_manifest_bytes)
        if data is None:
            collector.gap("size-limit", "Manifest exceeds the size limit.", display)
        elif lowered == "package.json":
            _inspect_package_json(collector, data, parts, display, in_archive=False)
        elif lowered.endswith(".deps.json"):
            _inspect_deps_json(collector, data, display)
        else:
            _inspect_runtimeconfig(collector, data, display)
        return
    if lowered.endswith(_JS_SUFFIXES):
        if "node_modules" in parts:
            return
        data = _read_bounded(path, limits.max_text_bytes)
        if data is None:
            collector.gap("size-limit", "Script exceeds the size limit; not inspected.", display)
            return
        _inspect_javascript(collector, data, display)
        return
    if size < 64:
        return
    with path.open("rb") as handle:
        magic = handle.read(4)
        if not magic.startswith(_BINARY_MAGICS):
            return
        if size > limits.max_binary_bytes:
            collector.gap("size-limit", "Binary exceeds the size limit; not inspected.", display)
            return
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            _inspect_binary(collector, mapped, display)


def scan_path(target: Path, limits: Limits | None = None) -> Inventory:
    limits = limits or Limits()
    if not target.exists():
        raise GatekeeperError(f"target does not exist: {target}")
    collector = _Collector()
    root = target.resolve()
    if root.is_file():
        collector.inventory.files_examined = 1
        _guarded(collector, root, (root.name,), root.name, limits)
        return collector.inventory
    stack: list[tuple[Path, tuple[str, ...]]] = [(root, ())]
    skipped_links = 0
    while stack:
        directory, prefix = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            collector.gap(
                "unreadable",
                f"Directory could not be listed: {error.strerror}.",
                "/".join(prefix) or ".",
            )
            continue
        for entry in entries:
            parts = (*prefix, entry.name)
            display = "/".join(parts)
            try:
                if _is_link(entry):
                    skipped_links += 1
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if len(parts) >= limits.max_depth:
                        collector.gap("depth-limit", "Directory nesting limit reached.", display)
                        continue
                    stack.append((Path(entry.path), parts))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
            except OSError as error:
                collector.gap("unreadable", f"Entry could not be read: {error.strerror}.", display)
                continue
            if collector.inventory.files_examined >= limits.max_files:
                collector.gap("file-limit", f"Stopped after {limits.max_files} files.")
                stack.clear()
                break
            collector.inventory.files_examined += 1
            _guarded(collector, Path(entry.path), parts, display, limits)
    if skipped_links:
        collector.gap(
            "links-skipped",
            f"Skipped {skipped_links} symbolic links or junctions (never followed).",
            blocking=False,
        )
    return collector.inventory


def _guarded(collector: _Collector, path: Path, parts: tuple[str, ...], display: str, limits: Limits) -> None:
    try:
        _inspect_file(collector, path, parts, display, limits)
    except (OSError, ValueError) as error:
        collector.gap("unreadable", f"File could not be inspected: {error}.", display)
