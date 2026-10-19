# Testing the software trust toolkit on real software

[Software Intake Gatekeeper](https://github.com/Sushant-Nemade/software-intake-gatekeeper) and
[Privacy Flow Inspector](https://github.com/Sushant-Nemade/privacy-flow-inspector) were first
built and tested against fictional demos. Fixtures prove the code works; they do not prove the
tools are useful. So both tools were pointed at real software. Each run found something, and each
run also exposed a weakness in the tool itself, which was fixed and released.

Runs from 2026-10-15 (sections 1 and 2) and 2026-10-18 (section 3). Findings are technical
evidence, not legal advice and not proof that any project is exploitable.

## 1. Privacy Flow Inspector on my own portfolio website

**Setup.** Real Chromium (Playwright) opened https://sushant-nemade.github.io, ran a few terminal
commands, typed a test email address into the command input and scrolled the page. The session
was saved as a HAR file and scanned with `privacy-flow-inspector` 0.1.1 from PyPI.

**Result.** APPROVE, 0 findings, 8 requests. The typed test email went nowhere. Good news, but
the report did not mention that the page loaded fonts from `fonts.googleapis.com` and
`fonts.gstatic.com`. Every visitor's browser sent its IP address, browser details and (for the
stylesheet) the page address to Google. In January 2022 a German court (LG München I,
judgment of 20 January 2022, 3 O 17493/20) found that embedding Google Fonts this way without
consent breached GDPR.

**What changed in the tool ([v0.2.0](https://github.com/Sushant-Nemade/privacy-flow-inspector/releases/tag/v0.2.0)).**
- Every report now lists all third-party recipients with request counts, even when no personal
  data appears in the request content.
- New opt-in rule `PFI-THIRD-PARTY-CONNECTION` treats each third-party connection as an IP-address
  flow. It also notes when a `Referer` header revealed which page was viewed.

**What changed on the website.** Archivo and JetBrains Mono are now self-hosted (four woff2
files, SIL Open Font License 1.1, license texts included). The page looks the same.

| Live website scan, connection rule on | Third parties | Decision |
|---|---|---|
| Before (Google Fonts) | fonts.googleapis.com (1 request), gstatic.com (2) | REVIEW, 2 low findings |
| After (self-hosted fonts) | none | APPROVE |

## 2. Software Intake Gatekeeper on a real Electron update

**Setup.** [MarkText](https://github.com/marktext/marktext), an open-source (MIT) Markdown editor
built on Electron. The official Windows zips of 0.21.1 and 0.21.2 were downloaded from its GitHub
releases, verified against the published `SHA256SUMS.txt`, unpacked to a temp folder and compared
with `intake-gatekeeper diff 0.21.1 0.21.2 --osv`. Nothing was installed or executed, and no
MarkText files were committed anywhere.

**Scale.** 108 files, 20,072 entries inside `app.asar`, 505 npm packages, live OSV lookup,
about 30 seconds.

**The first run (v0.2.1) exposed two weaknesses in the tool.**
- 10 "new" and 10 "resolved" code findings that were the same code. The bundler renames its
  output every build (`index-BBEVtY79.js` became `index-Cz8Eo_n9.js`), and the tool matched
  findings by file name.
- 44 "new" and 62 "removed" network endpoints, mostly URLs from comments and license headers in
  bundled libraries (`css-tricks.com`, `datatracker.ietf.org`, ...), not real network calls.

**Fixes ([v0.2.2](https://github.com/Sushant-Nemade/software-intake-gatekeeper/releases/tag/v0.2.2)).**
Content hashes in bundle names are ignored when matching, and endpoints only count URLs that
start a string literal.

| MarkText 0.21.1 to 0.21.2 | v0.2.1 | v0.2.2 |
|---|---|---|
| New code findings | 10 (false) | 0 |
| New / removed endpoints | 44 / 62 | 1 / 0 |
| Resolved advisories | 27 | 27 |
| Decision | REVIEW | REVIEW |

**What the update actually changes.** It resolves 27 known advisories (axios 12, brace-expansion 6,
mermaid 5, dompurify 3, source-map-js 1), adds 49 npm packages and changes two native modules and
the main executable. The single new endpoint is an Eclipse modeling namespace string from a
diagram layout library, not a network call. REVIEW (not APPROVE) is right here: an update that
adds 49 packages deserves a quick look, even though it mostly fixes things.

**Absolute scan of 0.21.2, for context.** Electron 42.1.0; the fuses are left at Electron's
defaults (for example RunAsNode enabled), which is common. Two windows set `webSecurity: false`
together with `sandbox: true` and `nodeIntegration: false`; this is visible in MarkText's public
source (`packages/desktop/src/main/config.ts`). 26 high-rated advisories remain in bundled
packages (for example @xmldom/xmldom, fast-uri, js-yaml) and Electron 42.1.0 itself. These are
version-level matches against public advisories, not proof that MarkText is exploitable.

## 3. Version 3: every new parser checked against real artifacts

Both tools are at v0.3.0 on PyPI and the GitHub Marketplace. Each new capability was checked
against real files and official tools before release, and CI keeps checking them:

| New capability | Real-world check | Result |
|---|---|---|
| Rust crates (`cargo auditable`) | Alpine Linux's official `ripgrep` 14.1.1 binary; CI builds on Linux, Windows and macOS compared with the official `rust-audit-info` decoder | 42 crates, every one matching ripgrep's `Cargo.lock`; identical to `rust-audit-info` on all three systems |
| Java (Maven) | `log4j-core` 2.14.1 from Maven Central (SHA-1 checked), nested in a Spring Boot style JAR | Log4Shell (CVE-2021-44228) found inside `BOOT-INF/lib` |
| Python packages | `requests` 2.25.0, `urllib3` 1.26.4 and `Jinja2` 2.11.2 installed by pip | 20 known advisories, including CVE-2023-32681 |
| Code signing | VS Code, Node.js, Git and uv on Windows | Signer and SHA-1 thumbprint identical to Windows' `Get-AuthenticodeSignature` |
| WebSocket messages | Chrome DevTools export format, checked against the DevTools source | Email found inside a Socket.IO chat message |
| Compressed payloads | gzip + Base64 inside JSON, recorded with real Chromium | Email found, evidence key `$<json>.payload<base64+gzip><json>.input.email` |

A real Playwright capture also showed that Playwright never stores WebSocket messages and stores
gzip request bodies in a damaged form. The inspector used to pass those silently; v0.3.0 reports
them as coverage gaps, and a ready-made [Node.js Playwright fixture](https://github.com/Sushant-Nemade/privacy-flow-inspector/tree/main/examples/playwright-node)
now records WebSocket messages. In CI, the Python and Node.js recordings must produce identical
findings.

## What I learned

- Real data finds bugs that fixtures do not. Every test above led to a released fix.
- A clean APPROVE can hide context. Listing recipients by default is more honest than only
  listing detected data, and an unrecorded WebSocket is a gap, not a pass.
- Diffs need stable identities. Build artefacts (hashes, comments) are noise, not change.
- Parsers for untrusted files should be checked against the official tool for the same format,
  on every platform, in CI.
