<!-- Project URL: https://github.com/fmuecke/network-sandbox -->

# network-sandbox

An allowlisting HTTP proxy for Windows that limits which network destinations an AI agent can reach.

It listens on `127.0.0.1` only, forwards requests to whitelisted hosts, blocks everything else, and logs every decision. It's a single `.exe`: no installer, no dependencies, no admin rights.

## Why

Firewall the agent's Windows user to loopback only, and it has no network. Add the proxy, and it reaches only the `host:port` pairs you allow:

```
agent (restricted user) ──► network-sandbox (127.0.0.1:8080) ──► api.anthropic.com:443  ✔
                                                            ╳ ──► anything else        ✘ 403
```

## Quick start

1. Build it (needs [Go](https://go.dev/dl/)):

   ```powershell
   ./build.ps1          # runs all tests and creates out\network-sandbox.exe
   ```

2. Run it once. Without a config, it writes an example `network-sandbox.ini` next to the exe and exits:

   ```powershell
   .\out\network-sandbox.exe
   ```

3. Edit the whitelist in `out\network-sandbox.ini`, then start the proxy in the background:

   ```powershell
   .\out\network-sandbox.exe start
   ```

4. Point the agent at it:

   ```powershell
   $env:HTTPS_PROXY = 'http://127.0.0.1:8080'
   $env:HTTP_PROXY  = 'http://127.0.0.1:8080'
   claude
   ```

   Claude Code, curl, git, npm, pip and most other tools honor these.

## Configuration

```ini
[network-sandbox]
port=8080                      # required, 1-65535
logfile=network-sandbox.log    # optional; relative paths resolve next to the exe
loglevel=info                  # optional: error | warn | info | debug
privateaddresses=deny          # optional: deny | allow

[whitelist]
api.anthropic.com:443
claude.ai:443
github.com:443
*.githubusercontent.com:443
```

Whitelist entries, one per line:

| Entry | Allows |
|---|---|
| `github.com:443` | exactly `github.com` on port 443 |
| `*.githubusercontent.com:443` | any subdomain, e.g. `raw.githubusercontent.com`, but not `githubusercontent.com` itself |
| `140.82.112.3:443` | requests to that literal IP address |
| `[2001:db8::1]:443` | requests to that literal IPv6 address |

- The port is required. To allow a host on both 80 and 443, list it twice.
- Matching ignores case and a trailing dot.
- A request for `github.com` never matches an IP entry, even if the name resolves to that IP.
- A hostname entry connects to public addresses only. If the name resolves to a loopback, private or link-local address, the request gets `403`, so DNS can't point an allowed name at your machine or local network. For internal hosts, set `privateaddresses=allow`, which lifts this for all hostname entries. IP entries are always connected as written.
- `#` or `;` start a comment.

The proxy refuses to start on unknown keys, malformed entries or an empty whitelist. Config changes take effect after a restart.

## Commands

```
network-sandbox.exe [start|stop|restart|status] [-config <path>]
```

| Command | What it does |
|---|---|
| *(none)* | Runs in the console until Ctrl+C. |
| `start` | Runs in the background. |
| `stop` | Stops the background proxy. |
| `restart` | Stops and starts, e.g. after editing the config. |
| `status` | Lists all running proxies with their PID, listen address and config. Exit code 0 if any runs, 3 if not. |

`-help`, `-?` or `/?` shows all options. The default config is `network-sandbox.ini` next to the exe. The background proxy is recorded in `<config>.pid` next to the config, e.g. `network-sandbox.ini.pid`.

Each config has its own proxy, so you can run several side by side on different ports. `start`, `stop` and `restart` act on the proxy of the given config. `status -config <path>` checks only that config's background proxy.

## What the agent sees

- **Allowed:** the request goes through unchanged.
- **Blocked:** `403 Forbidden` with the reason, e.g. `network-sandbox: example.com:443 not in whitelist` or `... resolves to a non-public address`. Browsers show a generic tunnel error for blocked HTTPS instead.
- **Target unreachable:** `502 Bad Gateway`.

## Logs

In console mode, logs go to both stdout and the configured log file.

One line per request or HTTPS tunnel:

```
time=2026-09-30T06:23:36.019+02:00 level=INFO msg=request client=127.0.0.1:60273 method=CONNECT target=api.anthropic.com:443 decision=allow status=200 bytes_up=671 bytes_down=3904 duration=161.6331ms
time=2026-09-30T06:23:36.200+02:00 level=INFO msg=request client=127.0.0.1:60278 method=CONNECT target=www.wikipedia.org:443 decision=deny status=403 bytes_up=0 bytes_down=0 duration=0s
```

To find out which hosts a tool needs, run it through the proxy and look for `decision=deny`. With `loglevel=debug`, plain-HTTP requests also log their URL and headers. The URL is logged without user info and query string, and only a few harmless header values (such as `Content-Type` and `User-Agent`) are shown; a secret in the URL path would still be logged.

The log rotates at 10 MB and keeps the three previous files (`.1` to `.3`), so it never takes more than 40 MB. Give each config its own `logfile`.

## Company networks with TLS inspection

Behind a firewall that inspects TLS (for example FortiGate), the proxy needs no configuration because it passes HTTPS through untouched. The agent's tools must trust the company CA:

- **Windows certificate store:** PowerShell, .NET, `curl.exe` and git with `http.sslBackend=schannel` use it. If IT hasn't deployed the CA machine-wide, import it for the agent user:

  ```powershell
  Import-Certificate -FilePath company-ca.cer -CertStoreLocation Cert:\CurrentUser\Root
  ```

- **Own CA bundle:** these tools need the CA as a PEM file:

  | Tool | Setting |
  |---|---|
  | Node.js (Claude Code, npm) | `NODE_EXTRA_CA_CERTS=C:\path\company-ca.pem` |
  | Python (pip, requests) | `REQUESTS_CA_BUNDLE`, `PIP_CERT` or `SSL_CERT_FILE` |
  | git with OpenSSL | `git config --global http.sslCAInfo C:\path\company-ca.pem` |

Errors like `self-signed certificate in certificate chain` mean the tool is missing the CA, not that the proxy blocked something.

## Trying it out

- `./demo.ps1` sends real requests through the built proxy with curl. It needs internet access.
- To browse through the proxy with Edge, use a separate profile:

  ```powershell
  & "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe" `
      --user-data-dir="$env:TEMP\edge-sandbox" --proxy-server="http://127.0.0.1:8080" --no-first-run
  ```

  Expect many blocked requests: websites load assets from many domains, and Edge contacts Microsoft services in the background.

## Securing the setup

The proxy contains an agent only together with these:

- The agent runs as a separate, restricted Windows user.
- Firewall rules allow that user loopback traffic only.
- The proxy runs under a different account than the agent.
- The agent user can't modify the exe, the config or the log files, and can't create files in the config's directory, which holds the PID file.

## Limitations

- For HTTPS, the proxy controls only `host:port`, not paths or content. It doesn't check the TLS server name either: where several sites share servers (a CDN), a tunnel to an allowed host can ask for another site on them.
- Allowed hosts can still carry data out, e.g. by pushing to GitHub. Keep the whitelist short.
- DNS lookups made directly through the Windows DNS service aren't covered.
- Any local process can use the proxy; there is no authentication. It only ever grants whitelisted access.
- At most 256 connections at a time; further clients wait. A tunnel or transfer without traffic for 15 minutes is closed. A client can still use up these limits, or flood the log until older entries rotate out.
- No SOCKS, no UDP, no Windows service.

Full specification: [doc/spec.md](doc/spec.md).

## License

[GPL-3.0-or-later](LICENSE) © 2026 Florian Mücke
