"""Report renderers: JSON, CycloneDX 1.6, SARIF 2.1.0, Markdown and terminal text."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import quote

from intake_gatekeeper.diff import UpdateDiff
from intake_gatekeeper.engine import severity_counts
from intake_gatekeeper.model import Finding, Report, Severity, clean_text, version_key
from intake_gatekeeper.rules import ELECTRON_SECURITY, RULES

TOOL_NAME = "software-intake-gatekeeper"
TOOL_URL = "https://github.com/Sushant-Nemade/software-intake-gatekeeper"
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}


def _timestamp(report: Report) -> str:
    return report.scanned_at.strftime("%Y-%m-%dT%H:%M:%SZ")


def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _location_dict(finding: Finding) -> dict[str, Any] | None:
    if finding.location is None:
        return None
    location = finding.location
    return {
        key: value
        for key, value in (
            ("path", location.path),
            ("line", location.line),
            ("column", location.column),
            ("snippet", location.snippet),
        )
        if value is not None
    }


def _report_document(report: Report) -> dict[str, Any]:
    inventory = report.inventory
    document: dict[str, Any] = {
        "schema": "software-intake-gatekeeper/report/v1",
        "tool": {"name": TOOL_NAME, "version": report.tool_version},
        "target": report.target,
        "scanned_at": _timestamp(report),
        "vulnerability_lookup": report.lookup,
        "decision": {"value": report.decision.value, "reasons": report.decision_reasons},
        "summary": {
            "files_examined": inventory.files_examined,
            "archive_entries_examined": inventory.archive_entries_examined,
            "components": len(inventory.components),
            "findings_by_severity": severity_counts(inventory.findings),
            "waived_findings": sum(1 for f in inventory.findings if f.waived),
        },
        "electron": [
            {"executable": info.executable, "version": info.version, "fuses": info.fuses}
            for info in inventory.electron
        ],
        "components": [
            {
                "ecosystem": c.ecosystem,
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "kind": c.kind,
                "vulnerability_lookup": c.queryable,
                "note": c.note,
                "occurrences": c.occurrences,
                "locations": [location.path for location in c.locations],
            }
            for c in inventory.components
        ],
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.label,
                "title": f.title,
                "message": f.message,
                "location": _location_dict(f),
                "component": f.component_purl,
                "aliases": list(f.vulnerability.aliases) if f.vulnerability else [],
                "fixed_versions": list(f.vulnerability.fixed_versions) if f.vulnerability else [],
                "nearest_fix": f.vulnerability.nearest_fix if f.vulnerability else None,
                "waiver": f.waiver_reason,
            }
            for f in inventory.findings
        ],
        "coverage_gaps": [
            {"code": g.code, "message": g.message, "path": g.path, "blocking": g.blocking}
            for g in inventory.gaps
        ],
        "endpoints": dict(sorted(inventory.endpoints.items())),
        "binaries": [
            {
                "path": b.path,
                "size": b.size,
                "sha256": b.sha256,
                "kind": b.kind,
                "signer": (
                    {"subject": b.signer, "issuer": b.signer_issuer, "sha1_thumbprint": b.signer_sha1}
                    if b.signer
                    else None
                ),
            }
            for b in sorted(inventory.binaries, key=lambda b: b.path)
        ],
    }
    return document


def to_json(report: Report) -> str:
    return json.dumps(_report_document(report), indent=2, ensure_ascii=False) + "\n"


def _cyclonedx_severity(finding: Finding) -> str:
    vulnerability = finding.vulnerability
    if vulnerability is None or vulnerability.severity is None:
        return "unknown"
    return vulnerability.severity.label


def _cvss_method(vector: str) -> str:
    if vector.startswith("CVSS:3.1/"):
        return "CVSSv31"
    if vector.startswith("CVSS:3.0/"):
        return "CVSSv3"
    if vector.startswith("CVSS:4.0/"):
        return "CVSSv4"
    return "other"


def to_cyclonedx(report: Report) -> str:
    inventory = report.inventory
    digest = hashlib.sha256(
        json.dumps([_timestamp(report), report.target, [c.purl for c in inventory.components]]).encode()
    ).hexdigest()
    components = []
    for component in inventory.components:
        entry: dict[str, Any] = {
            "type": {"framework": "framework", "application": "application"}.get(component.kind, "library"),
            "bom-ref": component.purl,
            "name": component.name,
            "version": component.version,
            "purl": component.purl,
            "properties": [
                {"name": "intake-gatekeeper:ecosystem", "value": component.ecosystem},
                {
                    "name": "intake-gatekeeper:vulnerability-lookup",
                    "value": str(component.queryable).lower(),
                },
            ],
        }
        if component.locations:
            entry["evidence"] = {
                "occurrences": [{"location": location.path} for location in component.locations]
            }
        components.append(entry)
    vulnerabilities = []
    for finding in inventory.findings:
        vulnerability = finding.vulnerability
        if vulnerability is None or finding.component_purl is None:
            continue
        ratings: list[dict[str, Any]] = [
            {
                "source": {"name": vulnerability.severity_source},
                "severity": _cyclonedx_severity(finding),
            }
        ]
        ratings += [
            {"method": _cvss_method(vector), "vector": vector} for vector in vulnerability.cvss_vectors
        ]
        item: dict[str, Any] = {
            "bom-ref": f"{vulnerability.id}|{finding.component_purl}",
            "id": vulnerability.id,
            "source": {"name": "OSV", "url": vulnerability.url},
            "ratings": ratings,
            "description": vulnerability.summary,
            "affects": [{"ref": finding.component_purl}],
        }
        if vulnerability.aliases:
            item["references"] = [
                {
                    "id": alias,
                    "source": {
                        "name": "OSV",
                        "url": f"https://osv.dev/vulnerability/{quote(alias, safe='-_.')}",
                    },
                }
                for alias in vulnerability.aliases
            ]
        if vulnerability.fixed_versions:
            item["recommendation"] = "Upgrade to a fixed version: " + ", ".join(vulnerability.fixed_versions)
        if finding.waiver_reason:
            item["analysis"] = {"detail": f"Waived by intake policy: {finding.waiver_reason}"}
        vulnerabilities.append(item)
    document: dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, TOOL_URL + '/' + digest)}",
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(report),
            "tools": {
                "components": [{"type": "application", "name": TOOL_NAME, "version": report.tool_version}]
            },
            "component": {"type": "application", "bom-ref": "intake-target", "name": report.target},
        },
        "components": components,
    }
    if vulnerabilities:
        document["vulnerabilities"] = vulnerabilities
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _sarif_level(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _sarif_uri(path: str) -> str:
    return quote(path, safe="/!._-~@+")


def sarif_prefix(target: Path, cwd: Path) -> str:
    """Prefix that makes target-relative paths relative to cwd, or '' if target is outside it."""
    resolved = target.resolve()
    base = resolved if resolved.is_dir() else resolved.parent
    try:
        relative = base.relative_to(cwd.resolve()).as_posix()
    except ValueError:
        return ""
    return "" if relative == "." else relative + "/"


def to_sarif(report: Report, uri_prefix: str = "") -> str:
    rules: list[dict[str, Any]] = []
    indexes: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    for finding in report.inventory.findings:
        if finding.rule_id not in indexes:
            indexes[finding.rule_id] = len(rules)
            rule = RULES.get(finding.rule_id)
            vulnerability = finding.vulnerability
            if rule is not None:
                name, text, help_uri = rule.title, rule.help, rule.help_uri
                tags = ["security", "electron"]
            else:
                name = clean_text(vulnerability.summary if vulnerability else finding.title, 200)
                text = f"Known vulnerability {finding.rule_id}: {name}"
                help_uri = vulnerability.url if vulnerability else ELECTRON_SECURITY
                tags = ["security", "vulnerability", "dependency"]
            descriptor: dict[str, Any] = {
                "id": finding.rule_id,
                "shortDescription": {"text": name},
                "fullDescription": {"text": text},
                "helpUri": help_uri,
                "help": {"text": text},
                "defaultConfiguration": {"level": _sarif_level(finding.severity)},
                "properties": {"tags": tags},
            }
            if finding.severity in _SECURITY_SEVERITY:
                descriptor["properties"]["security-severity"] = _SECURITY_SEVERITY[finding.severity]
            rules.append(descriptor)
        location = finding.location
        physical: dict[str, Any] = {
            "artifactLocation": {"uri": _sarif_uri(uri_prefix + (location.path if location else "."))}
        }
        if location is not None and location.line is not None:
            region: dict[str, Any] = {"startLine": location.line}
            if location.column is not None:
                region["startColumn"] = location.column
            if location.snippet:
                region["snippet"] = {"text": location.snippet}
            physical["region"] = region
        fingerprint = hashlib.sha256(
            "|".join(
                [finding.rule_id, finding.component_purl or "", location.path if location else ""]
            ).encode()
        ).hexdigest()
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": indexes[finding.rule_id],
            "level": _sarif_level(finding.severity),
            "message": {"text": clean_text(f"{finding.title}. {finding.message}", 2000)},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {"intakeGatekeeper/v1": fingerprint},
        }
        if finding.waiver_reason:
            result["suppressions"] = [{"kind": "external", "justification": finding.waiver_reason}]
        results.append(result)
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": report.tool_version,
                        "informationUri": TOOL_URL,
                        "rules": rules,
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": results,
                "properties": {"decision": report.decision.value},
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


_MD_SPECIAL = str.maketrans({c: f"\\{c}" for c in "\\`*_{}[]()<>#+-.!|~"})


def md(value: str, limit: int = 200) -> str:
    return clean_text(value, limit).translate(_MD_SPECIAL)


def code(value: str, limit: int = 160) -> str:
    return "`" + clean_text(value, limit).replace("`", "'").replace("|", "\u00a6") + "`"


_BADGE = {"approve": "APPROVE", "review": "REVIEW", "reject": "REJECT"}


def to_markdown(report: Report, max_findings: int = 50) -> str:
    inventory = report.inventory
    counts = severity_counts(inventory.findings)
    lines = [
        f"## Software Intake Gatekeeper: **{_BADGE[report.decision.value]}**",
        "",
        f"Target {code(report.target, 120)} scanned at {_timestamp(report)} "
        f"with vulnerability lookup **{report.lookup}**.",
        "",
    ]
    lines += [f"- {md(reason, 300)}" for reason in report.decision_reasons]
    lines += [
        "",
        "| Critical | High | Medium | Low | Info | Waived | Components | Files |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} "
        f"| {counts['info']} | {sum(1 for f in inventory.findings if f.waived)} "
        f"| {len(inventory.components)} | {inventory.files_examined} |",
        "",
    ]
    for info in inventory.electron:
        enabled = ", ".join(f"{md(k)}={md(v)}" for k, v in info.fuses.items())
        lines.append(f"**Electron** {md(info.version or 'unknown')} in {code(info.executable)}: {enabled}")
        lines.append("")
    signers: dict[str, int] = {}
    for binary in inventory.binaries:
        if binary.signer:
            signers[binary.signer] = signers.get(binary.signer, 0) + 1
    if signers:
        listed = ", ".join(f"{md(name, 80)} ({count})" for name, count in sorted(signers.items()))
        lines += [
            f"**Code signing** (claimed Authenticode signer, not verified): {listed}; "
            f"{len(inventory.binaries) - sum(signers.values())} binaries without an embedded signature.",
            "",
        ]
    affected: dict[str, list[Finding]] = {}
    for finding in inventory.findings:
        if finding.vulnerability is not None and finding.component_purl and not finding.waived:
            affected.setdefault(finding.component_purl, []).append(finding)
    if affected:
        lines += [
            "### Components with known vulnerabilities",
            "",
            "| Component | Advisories | Highest | Smallest listed fix above current |",
            "|---|---:|---|---|",
        ]
        ranked = sorted(affected.items(), key=lambda item: (-max(f.severity for f in item[1]), item[0]))
        for purl, items in ranked:
            fixes = [
                f.vulnerability.nearest_fix for f in items if f.vulnerability and f.vulnerability.nearest_fix
            ]
            highest = max(f.severity for f in items).label
            suggestion = max(fixes, key=lambda v: version_key(v) or ((), 0, "")) if fixes else "n/a"
            lines.append(f"| {code(purl, 120)} | {len(items)} | {highest} | {md(suggestion, 40)} |")
        lines += [
            "",
            "_The fix column is the highest of each advisory's nearest fixed version; confirm "
            "it against the release notes before upgrading._",
            "",
        ]
    if inventory.findings:
        lines += ["### Findings", "", "| Severity | ID | Finding | Location |", "|---|---|---|---|"]
        for finding in inventory.findings[:max_findings]:
            location = finding.location.path if finding.location else ""
            if finding.location and finding.location.line:
                location += f":{finding.location.line}"
            severity = finding.severity.label + (" (waived)" if finding.waived else "")
            lines.append(
                f"| {severity} | {md(finding.rule_id, 60)} | {md(finding.title, 160)} | {md(location, 160)} |"
            )
        if len(inventory.findings) > max_findings:
            remaining = len(inventory.findings) - max_findings
            lines.append(f"\n_{remaining} more findings in the JSON/SARIF reports._")
        lines.append("")
    if inventory.gaps:
        lines += ["### Coverage gaps", ""]
        for gap in inventory.gaps[:30]:
            tag = "blocking" if gap.blocking else "note"
            where = f" ({code(gap.path, 120)})" if gap.path else ""
            lines.append(f"- **{tag}** {md(gap.code, 40)}: {md(gap.message, 300)}{where}")
        if len(inventory.gaps) > 30:
            lines.append(f"- {len(inventory.gaps) - 30} more in the JSON report.")
        lines.append("")
    lines.append("_Static, version-level evidence. No code was executed and reachability was not analysed._")
    return "\n".join(lines) + "\n"


def to_text(report: Report, max_findings: int = 15) -> str:
    inventory = report.inventory
    counts = severity_counts(inventory.findings)
    ecosystems: dict[str, int] = {}
    for component in inventory.components:
        ecosystems[component.ecosystem] = ecosystems.get(component.ecosystem, 0) + 1
    lines = [
        f"Decision: {report.decision.value.upper()}",
        *[f"  - {clean_text(reason, 300)}" for reason in report.decision_reasons],
        f"Target: {clean_text(report.target, 120)} | files {inventory.files_examined} "
        f"| archive entries {inventory.archive_entries_examined} | lookup {report.lookup}",
        "Components: "
        + (", ".join(f"{name} {count}" for name, count in sorted(ecosystems.items())) or "none"),
        "Findings: " + ", ".join(f"{label} {count}" for label, count in counts.items()),
    ]
    for info in inventory.electron:
        version = clean_text(info.version or "unknown")
        lines.append(f"Electron {version} at {clean_text(info.executable, 160)}")
    for finding in inventory.findings[:max_findings]:
        where = finding.location.path if finding.location else ""
        if finding.location and finding.location.line:
            where += f":{finding.location.line}"
        lines.append(
            f"  [{finding.severity.label.upper():8}] {clean_text(finding.rule_id, 60)} "
            f"{clean_text(finding.title, 100)} @ {clean_text(where, 120)}"
            + (" (waived)" if finding.waived else "")
        )
    if len(inventory.findings) > max_findings:
        lines.append(f"  ... {len(inventory.findings) - max_findings} more (see --json/--sarif)")
    blocking = [gap for gap in inventory.gaps if gap.blocking]
    if blocking:
        lines.append(f"Blocking coverage gaps: {len(blocking)}")
        for gap in blocking[:10]:
            lines.append(f"  - {clean_text(gap.code, 40)}: {clean_text(gap.message, 200)}")
    return "\n".join(lines) + "\n"


def _finding_brief(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.label,
        "title": finding.title,
        "component": finding.component_purl,
        "location": _location_dict(finding),
        "waiver": finding.waiver_reason,
    }


def to_diff_json(diff: UpdateDiff) -> str:
    document = {
        "schema": "software-intake-gatekeeper/diff/v1",
        "tool": {"name": TOOL_NAME, "version": diff.new.tool_version},
        "old": {"target": diff.old.target, "decision": diff.old.decision.value},
        "new": {"target": diff.new.target, "decision": diff.new.decision.value},
        "decision": {"value": diff.decision.value, "reasons": diff.reasons},
        "components": [
            {
                "ecosystem": c.ecosystem,
                "name": c.name,
                "change": c.kind,
                "old": list(c.old),
                "new": list(c.new),
            }
            for c in diff.components
        ],
        "findings": {
            "new": [_finding_brief(f) for f in diff.new_findings],
            "resolved": [_finding_brief(f) for f in diff.resolved_findings],
            "persisting": diff.persisting_findings,
        },
        "electron": {
            "version": list(diff.electron_versions) if diff.electron_versions else None,
            "fuse_changes": [
                {
                    "executable": c.executable,
                    "fuse": c.fuse,
                    "old": c.old,
                    "new": c.new,
                    "weakened": c.weakened,
                }
                for c in diff.fuse_changes
            ],
        },
        "endpoints": {"added": diff.endpoints_added, "removed": diff.endpoints_removed},
        "binaries": {
            "added": diff.binaries_added,
            "removed": diff.binaries_removed,
            "changed": diff.binaries_changed,
        },
        "signatures": [
            {"path": c.path, "change": c.kind, "old_signer": c.old, "new_signer": c.new}
            for c in diff.signature_changes
        ],
        "reports": {"old": _report_document(diff.old), "new": _report_document(diff.new)},
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def diff_sarif(diff: UpdateDiff, uri_prefix: str = "") -> str:
    """SARIF for the new version, limited to findings the update introduced."""
    inventory = replace(diff.new.inventory, findings=diff.new_findings)
    return to_sarif(replace(diff.new, inventory=inventory, decision=diff.decision), uri_prefix)


def to_diff_markdown(diff: UpdateDiff, max_rows: int = 40) -> str:
    lines = [
        f"## Software Intake Gatekeeper update check: **{_BADGE[diff.decision.value]}**",
        "",
        f"{code(diff.old.target, 80)} to {code(diff.new.target, 80)}, vulnerability lookup "
        f"**{diff.new.lookup}**.",
        "",
    ]
    lines += [f"- {md(reason, 300)}" for reason in diff.reasons]
    added = sum(1 for c in diff.components if c.kind == "added")
    removed = sum(1 for c in diff.components if c.kind == "removed")
    changed = sum(1 for c in diff.components if c.kind == "changed")
    lines += [
        "",
        "| New findings | Resolved | Persisting | Components +/-/~ | New endpoints | New binaries |",
        "|---:|---:|---:|---:|---:|---:|",
        f"| {len(diff.new_findings)} | {len(diff.resolved_findings)} | {diff.persisting_findings} "
        f"| {added}/{removed}/{changed} | {len(diff.endpoints_added)} | {len(diff.binaries_added)} |",
        "",
    ]
    if diff.electron_versions:
        old, new = diff.electron_versions
        lines += [f"**Electron** {md(old or 'unknown')} to {md(new or 'unknown')}", ""]
    if diff.fuse_changes:
        lines += ["### Electron fuse changes", "", "| Fuse | Old | New | |", "|---|---|---|---|"]
        for change in diff.fuse_changes:
            flag = "**weakened**" if change.weakened else ""
            lines.append(
                f"| {md(change.fuse)} | {md(change.old or '-')} | {md(change.new or '-')} | {flag} |"
            )
        lines.append("")
    if diff.signature_changes:
        lines += [
            "### Code signing changes",
            "",
            "| File | Change | Old signer | New signer |",
            "|---|---|---|---|",
        ]
        for sig in diff.signature_changes[:max_rows]:
            label = f"**{sig.kind}**" if sig.needs_review else sig.kind
            lines.append(
                f"| {code(sig.path, 100)} | {label} "
                f"| {md(sig.old or 'unsigned', 80)} | {md(sig.new or 'unsigned', 80)} |"
            )
        lines += [
            "",
            "_Signer names are read from the embedded signature and not cryptographically verified._",
            "",
        ]
    if diff.new_findings:
        lines += ["### New findings", "", "| Severity | ID | Finding |", "|---|---|---|"]
        for finding in diff.new_findings[:max_rows]:
            severity = finding.severity.label + (" (waived)" if finding.waived else "")
            lines.append(f"| {severity} | {md(finding.rule_id, 60)} | {md(finding.title, 160)} |")
        lines.append("")
    if diff.resolved_findings:
        lines += ["### Resolved findings", "", "| Severity | ID | Finding |", "|---|---|---|"]
        for finding in diff.resolved_findings[:max_rows]:
            lines.append(
                f"| {finding.severity.label} | {md(finding.rule_id, 60)} | {md(finding.title, 160)} |"
            )
        lines.append("")
    if diff.components:
        lines += [
            "### Component changes",
            "",
            "| Component | Change | Old | New |",
            "|---|---|---|---|",
        ]
        for component in diff.components[:max_rows]:
            lines.append(
                f"| {code(component.ecosystem + ':' + component.name, 100)} | {component.kind} "
                f"| {md(', '.join(component.old) or '-', 60)} | {md(', '.join(component.new) or '-', 60)} |"
            )
        lines.append("")
    for title, items in (
        ("New network endpoints", diff.endpoints_added),
        ("Removed network endpoints", diff.endpoints_removed),
        ("New executables and native modules", diff.binaries_added),
        ("Changed executables and native modules", diff.binaries_changed),
    ):
        if items:
            lines += [f"### {title}", ""]
            lines += [f"- {code(item, 160)}" for item in items[:max_rows]]
            if len(items) > max_rows:
                lines.append(f"- {len(items) - max_rows} more in the JSON report.")
            lines.append("")
    lines.append(
        "_Persisting findings are not counted against the update; run `scan` for an absolute assessment._"
    )
    return "\n".join(lines) + "\n"


def to_diff_text(diff: UpdateDiff, max_rows: int = 15) -> str:
    lines = [
        f"Update decision: {diff.decision.value.upper()}",
        *[f"  - {clean_text(reason, 300)}" for reason in diff.reasons],
        f"Findings: {len(diff.new_findings)} new, {len(diff.resolved_findings)} resolved, "
        f"{diff.persisting_findings} persisting",
        f"Components changed: {len(diff.components)} | endpoints +{len(diff.endpoints_added)}/"
        f"-{len(diff.endpoints_removed)} | binaries +{len(diff.binaries_added)}/-{len(diff.binaries_removed)}"
        f"/~{len(diff.binaries_changed)}",
    ]
    if diff.electron_versions:
        old, new = diff.electron_versions
        lines.append(f"Electron: {clean_text(old or 'unknown')} -> {clean_text(new or 'unknown')}")
    for change in diff.fuse_changes:
        flag = " (weakened)" if change.weakened else ""
        lines.append(f"  fuse {change.fuse}: {change.old} -> {change.new}{flag}")
    for sig in diff.signature_changes:
        lines.append(
            f"  signature {sig.kind}: {clean_text(sig.path, 100)} "
            f"({clean_text(sig.old or 'unsigned', 60)} -> {clean_text(sig.new or 'unsigned', 60)})"
        )
    for finding in diff.new_findings[:max_rows]:
        lines.append(
            f"  NEW [{finding.severity.label.upper():8}] {clean_text(finding.rule_id, 60)} "
            f"{clean_text(finding.title, 100)}"
        )
    for host in diff.endpoints_added[:max_rows]:
        lines.append(f"  NEW endpoint {clean_text(host, 120)}")
    return "\n".join(lines) + "\n"
