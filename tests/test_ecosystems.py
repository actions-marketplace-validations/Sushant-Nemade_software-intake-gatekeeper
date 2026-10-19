from __future__ import annotations

import datetime
import io
import json
import os
import zipfile
import zlib
from pathlib import Path

import binfmt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from intake_gatekeeper import authenticode, objfile, output, packages, rust
from intake_gatekeeper.diff import compare
from intake_gatekeeper.engine import run_scan
from intake_gatekeeper.model import Decision
from intake_gatekeeper.policy import Policy
from intake_gatekeeper.scanner import Limits, scan_path

OFFLINE = Policy(require_vulnerability_lookup=False)
AUDIT = {
    "packages": [
        {"name": "demo-cli", "version": "0.4.0", "source": "local", "root": True, "dependencies": [1, 2, 3]},
        {"name": "smallvec", "version": "1.6.0", "source": "crates.io"},
        {"name": "cc", "version": "1.0.73", "source": "crates.io", "kind": "build"},
        {"name": "inhouse", "version": "2.0.0", "source": "git"},
    ]
}


def _audit_blob(document: dict[str, object] | None = None) -> bytes:
    return zlib.compress(json.dumps(document or AUDIT).encode())


def _write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_bytes(data)
    return path


def _signature(common_name: str, organization: str) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        ]
    )
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x0BADC0DE)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    blob = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"authenticode content stand-in")
        .add_signer(certificate, key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])
    )
    return blob


@pytest.mark.parametrize(
    "image",
    [
        binfmt.elf(".dep-v0", _audit_blob()),
        binfmt.elf(".dep-v0", _audit_blob(), big_endian=True),
        binfmt.pe(".dep-v0", _audit_blob()),
        binfmt.macho(".dep-v0", _audit_blob()),
        binfmt.macho(".dep-v0", _audit_blob(), fat=True),
    ],
    ids=["elf-le", "elf-be", "pe", "macho", "macho-universal"],
)
def test_cargo_auditable_in_every_object_format(image: bytes) -> None:
    crates = rust.read_audit_data(image)
    assert crates is not None
    assert [(c.name, c.version, c.build_only, c.root) for c in crates] == [
        ("demo-cli", "0.4.0", False, True),
        ("smallvec", "1.6.0", False, False),
        ("cc", "1.0.73", True, False),
        ("inhouse", "2.0.0", False, False),
    ]


def test_sections_outside_dep_v0_and_other_segments_are_ignored() -> None:
    assert rust.read_audit_data(binfmt.elf(".rodata", _audit_blob())) is None
    assert rust.read_audit_data(binfmt.macho(".dep-v0", _audit_blob(), segment="__TEXT")) is None
    assert rust.read_audit_data(binfmt.pe()) is None
    assert rust.read_audit_data(b"MZ" + bytes(200)) is None  # DOS stub without a PE header


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"not zlib", "not zlib"),
        (zlib.compress(b"[1, 2]"), "packages"),
        (zlib.compress(b'{"packages": [{"name": "x", "version": "1", "source": "crates.io"}]}'), "semver"),
        (
            zlib.compress(b'{"packages": [{"name": "a b", "version": "1.0.0", "source": "crates.io"}]}'),
            "name",
        ),
        (zlib.compress(b" " * (9 * 1024 * 1024)), "8 MiB"),
    ],
)
def test_malformed_audit_data_is_rejected(payload: bytes, message: str) -> None:
    with pytest.raises(rust.AuditDataError, match=message):
        rust.read_audit_data(binfmt.elf(".dep-v0", payload))


def test_truncated_headers_raise_format_errors() -> None:
    image = bytearray(binfmt.elf(".dep-v0", _audit_blob()))
    image[0x28:0x30] = (10**9).to_bytes(8, "little")
    with pytest.raises(rust.AuditDataError, match="malformed"):
        rust.read_audit_data(bytes(image))
    with pytest.raises(objfile.FormatError):
        objfile.find_section(binfmt.macho(".dep-v0", _audit_blob())[:40], ".dep-v0")


def test_rust_components_and_queryability(tmp_path: Path) -> None:
    _write(tmp_path / "bin" / "demo-cli", binfmt.elf(".dep-v0", _audit_blob()))
    inventory = scan_path(tmp_path)
    components = {c.purl: c for c in inventory.components}
    assert set(components) == {
        "pkg:cargo/demo-cli@0.4.0",
        "pkg:cargo/smallvec@1.6.0",
        "pkg:cargo/cc@1.0.73",
        "pkg:cargo/inhouse@2.0.0",
    }
    assert components["pkg:cargo/smallvec@1.6.0"].queryable
    assert components["pkg:cargo/demo-cli@0.4.0"].kind == "application"
    assert not components["pkg:cargo/cc@1.0.73"].queryable
    assert "Build-time" in (components["pkg:cargo/cc@1.0.73"].note or "")
    assert not components["pkg:cargo/inhouse@2.0.0"].queryable
    assert inventory.binaries[0].kind == "rust"


def test_authenticode_signer_is_read(tmp_path: Path) -> None:
    signer = authenticode.read_signer(binfmt.pe(certificate=_signature("Example Publisher", "Example Corp")))
    assert signer is not None
    assert signer.subject == "CN=Example Publisher, O=Example Corp"
    assert signer.issuer == signer.subject
    assert signer.serial == "0BADC0DE"
    assert len(signer.sha1) == 40 and len(signer.sha256) == 64
    assert authenticode.read_signer(binfmt.pe()) is None


def test_authenticode_rejects_garbage() -> None:
    with pytest.raises(authenticode.SignatureError):
        authenticode.read_signer(binfmt.pe(certificate=b"\x30\x03\x02\x01\x01"))
    with pytest.raises(authenticode.SignatureError):
        authenticode.parse_pkcs7(b"\x30\x84\xff\xff\xff\xff")


def test_update_check_flags_removed_and_changed_signatures(tmp_path: Path) -> None:
    acme, other = _signature("Acme Tools", "Acme"), _signature("Someone Else", "Elsewhere")
    renewed = _signature("Acme Tools", "Acme")
    for version, files in {
        "v1": {"app.exe": acme, "helper.exe": acme, "updater.exe": acme, "plugin.exe": None},
        "v2": {"app.exe": other, "helper.exe": None, "updater.exe": renewed, "plugin.exe": acme},
    }.items():
        for name, certificate in files.items():
            _write(tmp_path / version / name, binfmt.pe(".dep-v0", _audit_blob(), certificate))
    diff = compare(
        run_scan(tmp_path / "v1", OFFLINE, None), run_scan(tmp_path / "v2", OFFLINE, None), OFFLINE
    )
    kinds = {c.path: c.kind for c in diff.signature_changes}
    assert kinds == {
        "app.exe": "signer-changed",
        "helper.exe": "removed",
        "updater.exe": "certificate-renewed",
        "plugin.exe": "added",
    }
    assert diff.decision is Decision.REVIEW
    assert "1 executable(s) lost their code signature." in diff.reasons
    assert "1 executable(s) are signed by a different publisher." in diff.reasons
    document = json.loads(output.to_diff_json(diff))
    assert {s["change"] for s in document["signatures"]} == set(kinds.values())
    assert document["reports"]["new"]["binaries"][0]["signer"]["subject"] == "CN=Someone Else, O=Elsewhere"
    markdown = output.to_diff_markdown(diff)
    assert "### Code signing changes" in markdown and "**signer-changed**" in markdown


def test_renewed_certificate_alone_is_approved(tmp_path: Path) -> None:
    for version, certificate in (("v1", _signature("Acme", "Acme")), ("v2", _signature("Acme", "Acme"))):
        _write(tmp_path / version / "app.exe", binfmt.pe(".dep-v0", _audit_blob(), certificate))
    diff = compare(
        run_scan(tmp_path / "v1", OFFLINE, None), run_scan(tmp_path / "v2", OFFLINE, None), OFFLINE
    )
    assert [c.kind for c in diff.signature_changes] == ["certificate-renewed"]
    assert diff.decision is Decision.APPROVE


def test_python_distribution_metadata(tmp_path: Path) -> None:
    site = tmp_path / "resources" / "python" / "Lib" / "site-packages"
    _write(
        site / "Requests-2.25.0.dist-info" / "METADATA",
        "Metadata-Version: 2.1\nName: requests\nVersion: 2.25.0\n\nName: not-this\n",
    )
    _write(
        site / "Jinja2-2.11.2.dist-info" / "METADATA",
        "Metadata-Version: 2.1\nName: Jinja2\nVersion: 2.11.2\n",
    )
    _write(
        site / "zope.interface-5.0.egg-info" / "PKG-INFO",
        "Metadata-Version: 1.1\nName: zope.interface\nVersion: 5.0\n",
    )
    _write(site / "legacy_pkg-1.0-py3.8.egg-info", "Metadata-Version: 1.0\nName: Legacy_Pkg\nVersion: 1.0\n")
    _write(site / "broken-1.0.dist-info" / "METADATA", "Metadata-Version: 2.1\nSummary: no name\n")
    _write(site / "notes" / "METADATA", "Name: ignored\nVersion: 1.0\n")
    inventory = scan_path(tmp_path)
    assert {c.purl for c in inventory.components} == {
        "pkg:pypi/requests@2.25.0",
        "pkg:pypi/jinja2@2.11.2",
        "pkg:pypi/zope-interface@5.0",
        "pkg:pypi/legacy-pkg@1.0",
    }
    assert [(g.code, g.blocking) for g in inventory.gaps] == [("parse-error", False)]


def _jar(entries: dict[str, bytes | str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _pom(group: str, artifact: str, version: str) -> str:
    return f"#Generated by Maven\nversion={version}\ngroupId={group}\nartifactId={artifact}\n"


def test_java_archives_including_nested_and_shaded(tmp_path: Path) -> None:
    log4j = _jar(
        {
            "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties": _pom(
                "org.apache.logging.log4j", "log4j-core", "2.14.1"
            )
        }
    )
    shaded = _jar(
        {
            "META-INF/maven/com.example/tool/pom.properties": _pom("com.example", "tool", "1.0.0"),
            "META-INF/maven/com.google.guava/guava/pom.properties": _pom(
                "com.google.guava", "guava", "29.0-jre"
            ),
        }
    )
    plain = _jar({"com/example/Plain.class": b"\xca\xfe\xba\xbe"})
    fat = _jar({"BOOT-INF/lib/log4j-core-2.14.1.jar": log4j, "BOOT-INF/lib/plain.jar": plain})
    war = _jar({"WEB-INF/lib/service.jar": fat})
    _write(tmp_path / "lib" / "shaded.jar", shaded)
    _write(tmp_path / "app" / "service.war", war)
    _write(tmp_path / "lib" / "broken.jar", b"PK\x03\x04 not really a zip")
    inventory = scan_path(tmp_path)
    purls = {c.purl: c for c in inventory.components}
    assert set(purls) == {
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        "pkg:maven/com.example/tool@1.0.0",
        "pkg:maven/com.google.guava/guava@29.0-jre",
    }
    assert purls["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"].locations[0].path == (
        "app/service.war!/WEB-INF/lib/service.jar!/BOOT-INF/lib/log4j-core-2.14.1.jar!/"
        "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"
    )
    codes = {(g.code, g.blocking) for g in inventory.gaps}
    assert ("archive-entry", True) in codes  # broken.jar
    assert ("jar-unidentified", False) in codes  # plain.jar


def test_nested_archive_limits(tmp_path: Path) -> None:
    deep = _jar({"META-INF/maven/a/b/pom.properties": _pom("a", "b", "1.0")})
    for _ in range(3):
        deep = _jar({"lib/inner.jar": deep})
    _write(tmp_path / "deep.jar", deep)
    inventory = scan_path(tmp_path)
    assert inventory.components == []
    assert any("deeper than two levels" in g.message for g in inventory.gaps)
    big = _jar({"lib/big.jar": _jar({"filler.bin": os.urandom(4096)})})
    _write(tmp_path / "big" / "big.jar", big)
    limited = scan_path(tmp_path / "big", Limits(max_nested_archive_bytes=512))
    assert any("size limit" in g.message and g.blocking for g in limited.gaps)


def test_pom_properties_and_python_metadata_parsers() -> None:
    assert packages.parse_pom_properties(b"groupId=g\nartifactId=a\n") is None
    assert packages.parse_pom_properties(b"groupId=g x\nartifactId=a\nversion=1\n") is None
    assert packages.parse_python_metadata(b"Name: ../evil\nVersion: 1\n") is None
    assert packages.canonical_python_name("Zope.Interface__x") == "zope-interface-x"
