# Changelog

## [0.3.1]

- Added: `-config-json <json>` takes the config on the command line instead of a file. In the
  background, it is stored as `network-sandbox.inline-<port>.json` next to the exe until `stop`.

## [0.3.0] - 2026-10-07

- Changed: Configuration uses JSON instead of INI for better compatibility with configuration scripts
- Changed: Replaced term whitelist with allowlist.

## [0.2.1] - 2026-10-04

- Changed: The full console log now goes to stdout and the rotating log file, at the configured log
  level, if not run in background.

## [0.2.0] - 2026-09-30

- Security: The proxy bounds what clients can use of it. It serves at most 256 connections at a
  time, closes tunnels and transfers without traffic for 15 minutes and idle keep-alive connections
  after 2 minutes, and rotates the log at 10 MB, keeping three old files. Before, a client could
  hold unlimited idle connections and fill the disk through the log.
- Security: An allowed hostname connects to public addresses only. If it resolves to a
  loopback, private or link-local address, the request gets `403`. The new key
  `privateaddresses=allow` restores the old behavior for networks with internal hosts. IP entries
  are unaffected.
- Security: `loglevel=debug` no longer logs the user info and query string of URLs, and redacts
  all header values except a few harmless ones. Before, only four known headers were redacted.
- Security: The PID file is now `<config>.pid` (e.g. `network-sandbox.ini.pid`) and holds the PID
  and creation time of the proxy. Before, configs that differed only in the extension shared a PID
  file, a config named `*.pid` was overwritten, and `stop` could hit another process that reused
  the PID. `start`, `stop` and `restart` of one config no longer run concurrently, and `start`
  checks that its own process listens on the port.
  **Upgrading:** stop background proxies with the old version first. The new version ignores old
  PID files.
- Fixed: Plain-HTTP transfers that were aborted midway were missing from the log.
- Fixed: The README named `manual-tests.ps1`; the script is `demo.ps1`.
- Changed: (internal) The release workflow pins actions to commit SHAs, with Dependabot updating
  them. The Go module is named `github.com/fmuecke/network-sandbox`.
- Changed: `status` without `-config` lists every running proxy with its PID, listen address and
  config, including proxies that run in a console. Before, it reported only the background proxy
  of the default config. `status -config <path>` still checks that config's background proxy and
  prints the same details.
- Fixed: `status` and `stop` reported a running background proxy as "not running" after its exe
  file was renamed or replaced, e.g. by a rebuild.

## [0.1.1] - 2026-09-30

- Changed: Releases ship as `network-sandbox-<version>.zip` containing `network-sandbox.exe`,
  `README.md`, `LICENSE`, and `CHANGELOG.md`, instead of the bare exe. Both the zip and the exe
  carry build provenance.
- Changed: The release description lists the version's changes from `CHANGELOG.md` and links to
  the full changelog.

## [0.1.0] - 2026-09-30

- Added: Allowlisting HTTP proxy on `127.0.0.1`. It forwards plain-HTTP requests and HTTPS tunnels
  to allowed `host:port` pairs only and answers everything else with `403 Forbidden`.
- Added: INI configuration. Allowlist entries match exact hosts, `*.` subdomains, or literal IPv4
  and IPv6 addresses. The proxy refuses to start on unknown keys, malformed entries, or an empty
  allowlist; without a config, it writes an example next to the exe.
- Added: One log line per request or tunnel with its decision, status, and byte counts.
  `loglevel=debug` also logs plain-HTTP URLs and headers, with credentials redacted.
- Added: `start`, `stop`, `restart`, and `status` run and control the proxy in the background.
- Security: Release binaries carry SLSA build provenance, verifiable with
  `gh attestation verify <file> -R fmuecke/network-sandbox`.
- Changed: (internal) CI checks formatting, vets, tests, and builds on every push. Go files are
  pinned to LF line endings so the gofmt check passes on Windows checkouts, and CI actions run on
  Node.js 24.
