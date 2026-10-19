"""Compare two scanned versions of the same software and decide whether the update adds risk."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from intake_gatekeeper.electron import FUSE_RULES
from intake_gatekeeper.model import Decision, Finding, Report
from intake_gatekeeper.policy import Policy


@dataclass(frozen=True)
class ComponentChange:
    ecosystem: str
    name: str
    old: tuple[str, ...]
    new: tuple[str, ...]

    @property
    def kind(self) -> str:
        if not self.old:
            return "added"
        if not self.new:
            return "removed"
        return "changed"


@dataclass(frozen=True)
class FuseChange:
    executable: str
    fuse: str
    old: str | None
    new: str | None
    weakened: bool


@dataclass(frozen=True)
class SignatureChange:
    path: str
    old: str | None
    new: str | None
    kind: str  # removed, signer-changed, certificate-renewed or added

    @property
    def needs_review(self) -> bool:
        return self.kind in ("removed", "signer-changed")


@dataclass
class UpdateDiff:
    old: Report
    new: Report
    components: list[ComponentChange] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)
    persisting_findings: int = 0
    electron_versions: tuple[str | None, str | None] | None = None
    fuse_changes: list[FuseChange] = field(default_factory=list)
    endpoints_added: list[str] = field(default_factory=list)
    endpoints_removed: list[str] = field(default_factory=list)
    binaries_added: list[str] = field(default_factory=list)
    binaries_removed: list[str] = field(default_factory=list)
    binaries_changed: list[str] = field(default_factory=list)
    signature_changes: list[SignatureChange] = field(default_factory=list)
    decision: Decision = Decision.APPROVE
    reasons: list[str] = field(default_factory=list)


# Content hashes that bundlers put in file names (index-Cz8Eo_n9.js, main.3f2a1b9c.js) change every build.
_CONTENT_HASH = re.compile(r"([.-])(?=[A-Za-z_-]*\d)[A-Za-z0-9_-]{8,}(?=\.(?:m?js|cjs|css)$)")


def stable_path(path: str) -> str:
    head, slash, name = path.rpartition("/")
    return head + slash + _CONTENT_HASH.sub(r"\1*", name)


def _finding_key(finding: Finding) -> tuple[str, str]:
    if finding.component_purl:
        return finding.rule_id, finding.component_purl.rsplit("@", 1)[0]
    return finding.rule_id, stable_path(finding.location.path) if finding.location else ""


def _versions(report: Report) -> dict[tuple[str, str], set[str]]:
    versions: dict[tuple[str, str], set[str]] = {}
    for component in report.inventory.components:
        if component.kind == "application":
            continue
        versions.setdefault((component.ecosystem, component.name), set()).add(component.version)
    return versions


def compare(old: Report, new: Report, policy: Policy) -> UpdateDiff:
    diff = UpdateDiff(old=old, new=new)

    old_versions, new_versions = _versions(old), _versions(new)
    for key in sorted(old_versions.keys() | new_versions.keys()):
        before, after = old_versions.get(key, set()), new_versions.get(key, set())
        if before != after:
            diff.components.append(
                ComponentChange(key[0], key[1], tuple(sorted(before)), tuple(sorted(after)))
            )

    old_keys = {_finding_key(f) for f in old.inventory.findings}
    new_keys = {_finding_key(f) for f in new.inventory.findings}
    diff.new_findings = [f for f in new.inventory.findings if _finding_key(f) not in old_keys]
    diff.resolved_findings = [f for f in old.inventory.findings if _finding_key(f) not in new_keys]
    diff.persisting_findings = len(new.inventory.findings) - len(diff.new_findings)

    old_electron = {info.executable: info for info in old.inventory.electron}
    new_electron = {info.executable: info for info in new.inventory.electron}
    old_version = next((i.version for i in old.inventory.electron if i.version), None)
    new_version = next((i.version for i in new.inventory.electron if i.version), None)
    if old_version != new_version:
        diff.electron_versions = (old_version, new_version)
    risky = {fuse: state for fuse, state, _ in FUSE_RULES}
    for executable in sorted(old_electron.keys() | new_electron.keys()):
        old_fuses = old_electron[executable].fuses if executable in old_electron else {}
        new_fuses = new_electron[executable].fuses if executable in new_electron else {}
        for fuse in sorted(old_fuses.keys() | new_fuses.keys()):
            if old_fuses.get(fuse) != new_fuses.get(fuse):
                weakened = fuse in risky and new_fuses.get(fuse) == risky[fuse]
                diff.fuse_changes.append(
                    FuseChange(executable, fuse, old_fuses.get(fuse), new_fuses.get(fuse), weakened)
                )

    old_hosts, new_hosts = set(old.inventory.endpoints), set(new.inventory.endpoints)
    diff.endpoints_added = sorted(new_hosts - old_hosts)
    diff.endpoints_removed = sorted(old_hosts - new_hosts)

    old_bins = {b.path: b.sha256 for b in old.inventory.binaries}
    new_bins = {b.path: b.sha256 for b in new.inventory.binaries}
    diff.binaries_added = sorted(new_bins.keys() - old_bins.keys())
    diff.binaries_removed = sorted(old_bins.keys() - new_bins.keys())
    diff.binaries_changed = sorted(p for p in new_bins.keys() & old_bins.keys() if new_bins[p] != old_bins[p])

    old_by_path = {b.path: b for b in old.inventory.binaries}
    for binary in sorted(new.inventory.binaries, key=lambda b: b.path):
        previous = old_by_path.get(binary.path)
        if previous is None or previous.signer_sha1 == binary.signer_sha1:
            continue
        if previous.signer and not binary.signer:
            kind = "removed"
        elif not previous.signer:
            kind = "added"
        elif previous.signer != binary.signer:
            kind = "signer-changed"
        else:
            kind = "certificate-renewed"
        diff.signature_changes.append(SignatureChange(binary.path, previous.signer, binary.signer, kind))

    diff.decision, diff.reasons = _decide(diff, policy)
    return diff


def _decide(diff: UpdateDiff, policy: Policy) -> tuple[Decision, list[str]]:
    active = [f for f in diff.new_findings if not f.waived]
    at_reject = [f for f in active if f.severity >= policy.reject_at]
    at_review = [f for f in active if policy.review_at <= f.severity < policy.reject_at]
    weakened = [c for c in diff.fuse_changes if c.weakened]
    added_components = [c for c in diff.components if c.kind == "added"]
    blocking = [g for g in diff.new.inventory.gaps if g.blocking]
    reasons: list[str] = []
    if at_reject:
        reasons.append(f"{len(at_reject)} new finding(s) at or above {policy.reject_at.label}.")
    if at_review:
        reasons.append(
            f"{len(at_review)} new finding(s) between {policy.review_at.label} and {policy.reject_at.label}."
        )
    if weakened:
        reasons.append(f"{len(weakened)} Electron fuse(s) weakened.")
    removed = [c for c in diff.signature_changes if c.kind == "removed"]
    resigned = [c for c in diff.signature_changes if c.kind == "signer-changed"]
    if removed:
        reasons.append(f"{len(removed)} executable(s) lost their code signature.")
    if resigned:
        reasons.append(f"{len(resigned)} executable(s) are signed by a different publisher.")
    if diff.endpoints_added:
        reasons.append(f"{len(diff.endpoints_added)} new network endpoint(s) referenced by app code.")
    if diff.binaries_added:
        reasons.append(f"{len(diff.binaries_added)} new executable(s) or native module(s).")
    if added_components:
        reasons.append(f"{len(added_components)} new component(s).")
    if blocking:
        reasons.append(
            f"{len(blocking)} coverage gap(s) in the new version: "
            + "; ".join(sorted({g.code for g in blocking}))
            + "."
        )
    if at_reject:
        return Decision.REJECT, reasons
    if reasons:
        return Decision.REVIEW, reasons
    summary = "No new risk compared with the previous version"
    if diff.resolved_findings:
        summary += f"; {len(diff.resolved_findings)} finding(s) resolved"
    return Decision.APPROVE, [summary + "."]
