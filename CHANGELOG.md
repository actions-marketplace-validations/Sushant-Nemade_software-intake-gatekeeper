# Changelog

All notable changes are recorded here. The project follows [Semantic Versioning](https://semver.org/);
while the major version is 0, minor releases may change behaviour.

## [0.3.0] - 2026-10-18

### Added

- Rust inventory from `cargo auditable` data (`.dep-v0` section) in ELF, PE and Mach-O, including
  universal binaries, through a new bounded, dependency-free object-file reader. Build-only crates,
  the root package and non-crates.io sources are listed but not sent to OSV.
- Python inventory from `*.dist-info/METADATA` and `*.egg-info` metadata (`pkg:pypi`, PEP 503 names).
- Maven inventory from `pom.properties` inside `.jar`, `.war` and `.ear` files, including nested
  archives up to two levels (Spring Boot, WAR) read in memory with size and entry limits.
- Authenticode signer (subject, issuer, SHA-1 thumbprint) for PE files, without verification.
- Update check: removed signatures and a different signer on the same path need REVIEW; renewed
  certificates from the same signer and newly signed files are listed only.
- Real-artifact CI job on Linux, Windows and macOS: `cargo auditable` builds compared with
  `rust-audit-info`, Maven Central and PyPI artifacts with live OSV, and Windows'
  `Get-AuthenticodeSignature`.

### Changed

- The `nothing-recognized` gap now says how many binaries were fingerprinted without dependency data.
- Files that start with `MZ` but have no PE header are treated as non-PE instead of malformed.

## [0.2.2] - 2026-10-15

### Fixed

- Update check: code findings in bundles whose file names carry a content hash
  (`index-Cz8Eo_n9.js`, `main.3f2a1b9c.js`) are matched across versions instead of being reported
  as new and resolved. Found on a real MarkText 0.21.1 to 0.21.2 comparison, where it removed 10
  false new findings.
- Network endpoints only count URLs that start a string literal. URLs in comments and license
  headers are no longer reported; on the same comparison, new endpoints dropped from 44 to 1.

## [0.2.1] - 2026-10-15

### Added

- Published on PyPI: `python -m pip install software-intake-gatekeeper`. Releases are uploaded by
  the release workflow through PyPI trusted publishing, without a stored token.

### Changed

- README links are absolute so they also work on the PyPI project page.

## [0.2.0] - 2026-10-14

### Added

- `intake-gatekeeper diff OLD NEW`: compares two versions and decides on what the update adds.
  It reports new and resolved findings, component changes, Electron version and fuse changes
  (flagging weakened fuses), new or removed network endpoints and new, removed or changed
  executables and native modules. SARIF contains only the new findings.
- `compare-to` input for the GitHub Action to run the update check.
- Scan reports now list network endpoints referenced by app code and SHA-256 fingerprints of
  executables and native modules.
- Fictional two-version update demo in `examples/update-demo`.

### Changed

- The CLI shares its output options between `scan` and `diff`.

## [0.1.0] - 2026-10-14

First public release and first GitHub Marketplace listing.

### Added

- Read-only scanner for directories, Electron `.asar` archives and executables (PE, ELF, Mach-O).
- Inventories: Go build info (Go 1.18+), npm packages on disk and inside ASAR, NuGet `.deps.json`
  packages and runtime packs, .NET `runtimeconfig.json` frameworks, Electron runtime version.
- Electron hardening: fuse-wire decoding (9 fuses) and `webPreferences` rules with line, column and snippet evidence.
- Opt-in OSV.dev lookup: batching, pagination, retries, alias grouping, GHSA severity resolution and nearest fixed version.
- Policy file with thresholds, rule overrides and expiring, component-scoped waivers. APPROVE / REVIEW / REJECT decision; blocking coverage gaps prevent APPROVE.
- Reports: JSON, CycloneDX 1.6, SARIF 2.1.0 (paths relative to the working directory for code scanning) and Markdown.
- Composite GitHub Action with hash-pinned dependencies, job summary and `decision`, `sarif` and `sbom` outputs.

### Known limitations

- Version-level matching, not reachability analysis.
- No Rust `cargo auditable`, Python wheel, Java or native C/C++ inventories yet.
- Electron code rules detect literal settings only.

[0.3.0]: https://github.com/Sushant-Nemade/software-intake-gatekeeper/releases/tag/v0.3.0
[0.2.2]: https://github.com/Sushant-Nemade/software-intake-gatekeeper/releases/tag/v0.2.2
[0.2.1]: https://github.com/Sushant-Nemade/software-intake-gatekeeper/releases/tag/v0.2.1
[0.2.0]: https://github.com/Sushant-Nemade/software-intake-gatekeeper/releases/tag/v0.2.0
[0.1.0]: https://github.com/Sushant-Nemade/software-intake-gatekeeper/releases/tag/v0.1.0
