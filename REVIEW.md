# Review follow-ups

Deferred findings from the staged security, correctness, maintainability, and performance review on 2026-09-30.

## Medium: complete or narrow the public-address policy

`isPublic` combines `netip.Addr.IsGlobalUnicast`, `IsPrivate`, and a partial list of special-use prefixes. It currently allows several IANA ranges that are not globally reachable, including:

- IPv4: `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.
- IPv6: `64:ff9b:1::/48`, `100::/64`, `2001:2::/48`, `2001:db8::/32`, `3fff::/20`, and `5f00::/16`.

It also rejects all of `192.0.0.0/24`, including the globally reachable anycast addresses `192.0.0.9` and `192.0.0.10`.

Impact: a whitelisted hostname could resolve to a special-use range routed inside the local environment, while legitimate globally reachable exceptions can be blocked.

Follow-up:

- Either implement an ordered policy based on the IANA IPv4 and IPv6 Special-Purpose Address Registries' `Globally Reachable` field, including explicit exceptions, or narrow the documentation and names to the exact address categories being rejected.
- Add representative allowed and denied IPv4 and IPv6 registry cases to `TestIsPublic`.
- Record the registry revision if the prefixes are maintained in source.

References:

- <https://www.iana.org/assignments/iana-ipv4-special-registry>
- <https://www.iana.org/assignments/iana-ipv6-special-registry>

## Low: propagate PID-file read failures

`openBackground` treats every `os.ReadFile` error as if no PID file exists. Access denied and I/O failures therefore make `status -config` report `not running`, while `stop` can report success without stopping the process.

Follow-up:

- Return `not running` only for `fs.ErrNotExist`.
- Propagate other read errors with the PID-file path and underlying error.
- Add a focused test for a PID file that exists but cannot be read, if this can be made reliable on Windows CI.

The current PID plus process-creation-time identity and same-handle termination are sufficient when the config directory is protected; the sidecar does not also need the config path, executable path, or listen address.

## Low: make runtime log-rotation failures observable

`rotatingFile.rotate` ignores close and backup-rename errors. If renaming and truncating or reopening the active file both fail, log writes fail without an operator-visible diagnostic because `slog.Logger` discards handler errors.

Follow-up:

- Define whether persistent rotation failure should preserve the active log, use a separate diagnostic sink, or stop the proxy.
- Handle close and backup-rename failures according to that policy.
- Add fault-injection coverage for rename and reopen failures, in addition to the existing successful-rotation test.

## Verification context

- No high-severity finding remained in the reviewed staged snapshot.
- `git diff --cached --check` passed during the review.
- Build, race-detector, and `demo.ps1` 9/9 results were reported separately; they were not rerun during the staged-only review.
- The pinned GitHub Actions workflow had not yet run on GitHub.
