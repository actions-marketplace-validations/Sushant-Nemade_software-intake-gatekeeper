from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import quote

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")
_PURL_SAFE = "._-~"


class GatekeeperError(Exception):
    """A user-facing error that maps to exit status 2."""


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        normalized = value.strip().upper()
        if normalized == "MODERATE":
            normalized = "MEDIUM"
        try:
            return cls[normalized]
        except KeyError:
            raise ValueError(f"unknown severity {value!r}") from None

    @property
    def label(self) -> str:
        return self.name.lower()


class Decision(enum.Enum):
    APPROVE = "approve"
    REVIEW = "review"
    REJECT = "reject"


def clean_text(value: str, limit: int = 300) -> str:
    """Remove control and bidi characters from untrusted text and bound its length."""
    text = _CONTROL.sub("", value).replace("\n", " ").replace("\r", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


_NUMERIC_VERSION = re.compile(r"^v?(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$")


def version_key(version: str) -> tuple[tuple[int, ...], int, str] | None:
    """Order dotted numeric versions; pre-releases sort before the release. None if unparseable."""
    match = _NUMERIC_VERSION.match(version.strip())
    if match is None:
        return None
    numbers = tuple(int(part) for part in match.group(1).split("."))
    numbers = numbers + (0,) * max(0, 4 - len(numbers))
    prerelease = match.group(2)
    return (numbers, 0 if prerelease else 1, prerelease or "")


def nearest_fix(current: str, fixed: tuple[str, ...]) -> str | None:
    """Smallest listed fixed version above the current one, when versions are comparable."""
    current_key = version_key(current)
    if current_key is None:
        return None
    candidates = [
        (key, value) for value in fixed if (key := version_key(value)) is not None and key > current_key
    ]
    return min(candidates)[1] if candidates else None


def sort_versions(values: set[str]) -> tuple[str, ...]:
    parsed = sorted((key, value) for value in values if (key := version_key(value)) is not None)
    rest = sorted(value for value in values if version_key(value) is None)
    return tuple(value for _, value in parsed) + tuple(rest)


def build_purl(ecosystem: str, name: str, version: str) -> str:
    encoded_version = quote(version, safe=_PURL_SAFE)
    if ecosystem == "npm":
        if name.startswith("@") and "/" in name:
            scope, package = name.split("/", 1)
            scope_part = quote(scope, safe="")
            return f"pkg:npm/{scope_part}/{quote(package, safe=_PURL_SAFE)}@{encoded_version}"
        return f"pkg:npm/{quote(name, safe=_PURL_SAFE)}@{encoded_version}"
    if ecosystem == "Go":
        path = "/".join(quote(part, safe=_PURL_SAFE) for part in name.split("/"))
        return f"pkg:golang/{path}@{encoded_version}"
    if ecosystem == "NuGet":
        return f"pkg:nuget/{quote(name, safe=_PURL_SAFE)}@{encoded_version}"
    if ecosystem == "crates.io":
        return f"pkg:cargo/{quote(name, safe=_PURL_SAFE)}@{encoded_version}"
    if ecosystem == "PyPI":
        return f"pkg:pypi/{quote(name.lower(), safe=_PURL_SAFE)}@{encoded_version}"
    if ecosystem == "Maven":
        group, _, artifact = name.partition(":")
        return (
            f"pkg:maven/{quote(group, safe=_PURL_SAFE)}/{quote(artifact, safe=_PURL_SAFE)}@{encoded_version}"
        )
    raise ValueError(f"unsupported ecosystem {ecosystem!r}")


@dataclass(frozen=True)
class Location:
    path: str
    line: int | None = None
    column: int | None = None
    snippet: str | None = None


@dataclass
class Component:
    ecosystem: str
    name: str
    version: str
    kind: str = "library"
    queryable: bool = True
    note: str | None = None
    locations: list[Location] = field(default_factory=list)
    occurrences: int = 0

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)

    @property
    def purl(self) -> str:
        return build_purl(self.ecosystem, self.name, self.version)


@dataclass(frozen=True)
class Vulnerability:
    id: str
    aliases: tuple[str, ...]
    summary: str
    severity: Severity | None
    severity_source: str
    cvss_vectors: tuple[str, ...]
    fixed_versions: tuple[str, ...]
    nearest_fix: str | None = None

    @property
    def url(self) -> str:
        return f"https://osv.dev/vulnerability/{quote(self.id, safe='-_.')}"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    message: str
    location: Location | None = None
    component_purl: str | None = None
    vulnerability: Vulnerability | None = None
    waiver_reason: str | None = None

    @property
    def waived(self) -> bool:
        return self.waiver_reason is not None

    @property
    def identifiers(self) -> tuple[str, ...]:
        if self.vulnerability is None:
            return (self.rule_id,)
        return (self.vulnerability.id, *self.vulnerability.aliases)


@dataclass(frozen=True)
class Gap:
    code: str
    message: str
    path: str | None = None
    blocking: bool = True


@dataclass
class ElectronInfo:
    executable: str
    version: str | None
    fuses: dict[str, str]


@dataclass(frozen=True)
class BinaryInfo:
    path: str
    size: int
    sha256: str
    kind: str
    # Claimed Authenticode signer (not cryptographically verified); None when unsigned or not PE.
    signer: str | None = None
    signer_issuer: str | None = None
    signer_sha1: str | None = None


@dataclass
class Inventory:
    components: list[Component] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    electron: list[ElectronInfo] = field(default_factory=list)
    endpoints: dict[str, list[str]] = field(default_factory=dict)
    binaries: list[BinaryInfo] = field(default_factory=list)
    files_examined: int = 0
    archive_entries_examined: int = 0


@dataclass
class Report:
    tool_version: str
    target: str
    scanned_at: datetime
    lookup: str
    inventory: Inventory
    decision: Decision
    decision_reasons: list[str]
