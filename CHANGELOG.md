# Changelog

## [0.1.1] - 2026-09-30

- Changed: Releases ship as `network-sandbox-<version>.zip` containing `network-sandbox.exe`,
  `README.md`, `LICENSE`, and `CHANGELOG.md`, instead of the bare exe. Both the zip and the exe
  carry build provenance.
- Changed: The release description lists the version's changes from `CHANGELOG.md` and links to
  the full changelog.

## [0.1.0] - 2026-09-30

- Added: Allowlisting HTTP proxy on `127.0.0.1`. It forwards plain-HTTP requests and HTTPS tunnels
  to whitelisted `host:port` pairs only and answers everything else with `403 Forbidden`.
- Added: INI configuration. Whitelist entries match exact hosts, `*.` subdomains, or literal IPv4
  and IPv6 addresses. The proxy refuses to start on unknown keys, malformed entries, or an empty
  whitelist; without a config, it writes an example next to the exe.
- Added: One log line per request or tunnel with its decision, status, and byte counts.
  `loglevel=debug` also logs plain-HTTP URLs and headers, with credentials redacted.
- Added: `start`, `stop`, `restart`, and `status` run and control the proxy in the background.
- Security: Release binaries carry SLSA build provenance, verifiable with
  `gh attestation verify <file> -R fmuecke/network-sandbox`.
- Changed: (internal) CI checks formatting, vets, tests, and builds on every push. Go files are
  pinned to LF line endings so the gofmt check passes on Windows checkouts, and CI actions run on
  Node.js 24.
