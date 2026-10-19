"""Opt-in checks against real toolchains, registries and signed executables (enabled in CI)."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import httpx
import pytest

from intake_gatekeeper import authenticode, rust
from intake_gatekeeper.engine import run_scan
from intake_gatekeeper.osv import OsvClient
from intake_gatekeeper.policy import Policy

CENTRAL = "https://repo1.maven.org/maven2"


def _ids(report_findings: list, purl: str) -> set[str]:  # type: ignore[type-arg]
    return {
        identifier
        for finding in report_findings
        if finding.component_purl == purl
        for identifier in finding.identifiers
    }


@pytest.mark.skipif("INTAKE_RUST_BINARY" not in os.environ, reason="needs a cargo auditable build")
def test_cargo_auditable_build_matches_rust_audit_info(tmp_path: Path) -> None:
    binary = Path(os.environ["INTAKE_RUST_BINARY"])
    reference = json.loads(Path(os.environ["INTAKE_RUST_AUDIT_JSON"]).read_text(encoding="utf-8"))
    crates = rust.read_audit_data(binary.read_bytes())
    assert crates is not None
    ours = {(c.name, c.version, c.build_only, c.root) for c in crates}
    theirs = {
        (p["name"], p["version"], p.get("kind", "runtime") == "build", p.get("root", False))
        for p in reference["packages"]
    }
    assert ours == theirs
    assert ("smallvec", "1.6.0", False, False) in ours
    if os.environ.get("INTAKE_LIVE_OSV") == "1":
        (tmp_path / binary.name).write_bytes(binary.read_bytes())
        report = run_scan(tmp_path, Policy(), OsvClient())
        assert "RUSTSEC-2021-0003" in _ids(report.inventory.findings, "pkg:cargo/smallvec@1.6.0")


def _maven(client: httpx.Client, group: str, artifact: str, version: str) -> bytes:
    url = f"{CENTRAL}/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.jar"
    data = client.get(url).raise_for_status().content
    expected = client.get(url + ".sha1").raise_for_status().text.split()[0]
    assert hashlib.sha1(data, usedforsecurity=False).hexdigest() == expected
    return data


@pytest.mark.skipif(
    os.environ.get("INTAKE_LIVE_ARTIFACTS") != "1", reason="downloads from Maven Central and PyPI"
)
def test_real_maven_and_pypi_artifacts_with_live_osv(tmp_path: Path) -> None:
    with httpx.Client(timeout=60) as client:
        log4j = _maven(client, "org.apache.logging.log4j", "log4j-core", "2.14.1")
    with zipfile.ZipFile(tmp_path / "service.jar", "w") as fat:
        fat.writestr("BOOT-INF/lib/log4j-core-2.14.1.jar", log4j)
    site = tmp_path / "site-packages"
    pip = [sys.executable, "-m", "pip", "install", "--quiet", "--no-deps", "--target", str(site)]
    subprocess.run([*pip, "requests==2.25.0"], check=True)
    report = run_scan(tmp_path, Policy(), OsvClient())
    assert "CVE-2021-44228" in _ids(
        report.inventory.findings, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    )
    assert "CVE-2023-32681" in _ids(report.inventory.findings, "pkg:pypi/requests@2.25.0")


@pytest.mark.skipif("INTAKE_SIGNED_EXE" not in os.environ, reason="needs a signed PE and its expected signer")
def test_authenticode_matches_windows() -> None:
    signer = authenticode.read_signer(Path(os.environ["INTAKE_SIGNED_EXE"]).read_bytes())
    assert signer is not None
    assert signer.sha1 == os.environ["INTAKE_SIGNED_THUMBPRINT"].upper()
    assert f"CN={os.environ['INTAKE_SIGNED_CN']}" in signer.subject
