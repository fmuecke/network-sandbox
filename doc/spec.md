I want a simple network sandbox that does the following:
- listen on a configured port
- localhost, loopback only
- only forward traffic for allowed adresses (names and ip adresses)
- log traffic/requests to a file
- whitelist can be configured via a config file
- block all other network traffic
- run natively on windows

Purpose:
- effective limit web/network access for AI agents using this proxy
- work together with other tools that limit agent reach:
  - agent runs as a restricted user
  - firefall rules are restricted for that user to only allow loopback
  - (this tool) forward only legit network requests
- similar to GO Simple Tunnel: https://github.com/go-gost/gost, but as simple as possible



