"""Combine inventory, vulnerability lookup and policy into a report."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from intake_gatekeeper import __version__
from intake_gatekeeper.model import Finding, Gap, Location, Report, Severity
from intake_gatekeeper.osv import OsvClient
from intake_gatekeeper.policy import Policy, apply_policy, decide
from intake_gatekeeper.scanner import Limits, scan_path


def run_scan(
    target: Path,
    policy: Policy,
    osv: OsvClient | None,
    limits: Limits | None = None,
    now: datetime | None = None,
) -> Report:
    scanned_at = now or datetime.now(UTC)
    inventory = scan_path(target, limits)
    if not inventory.components and not inventory.findings and not inventory.electron:
        fingerprinted = len(inventory.binaries)
        detail = (
            f" {fingerprinted} binaries were fingerprinted but carry no readable dependency data."
            if fingerprinted
            else ""
        )
        inventory.gaps.append(
            Gap("nothing-recognized", "No supported packages or manifests were found." + detail)
        )
    queryable = [component for component in inventory.components if component.queryable]
    if osv is None:
        if queryable:
            inventory.gaps.append(
                Gap(
                    "lookup-disabled",
                    f"Known-vulnerability lookup was not run for {len(queryable)} component(s); "
                    "rerun with --osv.",
                    blocking=policy.require_vulnerability_lookup,
                )
            )
        lookup = "disabled"
    else:
        result = osv.lookup(inventory.components)
        inventory.gaps.extend(result.gaps)
        lookup = "osv"
        for component in inventory.components:
            for vulnerability in result.vulnerabilities.get(component.key, []):
                severity = vulnerability.severity or policy.unrated_vulnerability
                fixed = ", ".join(vulnerability.fixed_versions) or "no fixed version listed"
                if vulnerability.nearest_fix:
                    fixed = f"{vulnerability.nearest_fix} (nearest); all listed: {fixed}"
                rating = (
                    vulnerability.severity_source
                    if vulnerability.severity is not None
                    else f"unrated, treated as {severity.label} by policy"
                )
                inventory.findings.append(
                    Finding(
                        rule_id=vulnerability.id,
                        severity=severity,
                        title=f"{component.name} {component.version}: {vulnerability.summary}",
                        message=(
                            f"{component.purl} matches {vulnerability.id} by version "
                            f"(severity: {rating}). Fixed in: {fixed}. "
                            "Reachability was not analysed."
                        ),
                        location=component.locations[0] if component.locations else Location("."),
                        component_purl=component.purl,
                        vulnerability=vulnerability,
                    )
                )
    findings, policy_gaps = apply_policy(inventory.findings, policy, scanned_at.date())
    inventory.findings = sorted(
        findings,
        key=lambda f: (-int(f.severity), f.rule_id, f.location.path if f.location else ""),
    )
    inventory.gaps.extend(policy_gaps)
    decision, reasons = decide(inventory.findings, inventory.gaps, policy)
    return Report(
        tool_version=__version__,
        target=target.resolve().name or str(target),
        scanned_at=scanned_at,
        lookup=lookup,
        inventory=inventory,
        decision=decision,
        decision_reasons=reasons,
    )


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {severity.label: 0 for severity in reversed(Severity)}
    for finding in findings:
        if not finding.waived:
            counts[finding.severity.label] += 1
    return counts
