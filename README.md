# VANTAGE

A security assessment workbench for systems **you own or have written permission to test**. It runs DNS, email and web configuration checks, captures evidence for every finding, writes client-ready reports, and shows progress live in a local dashboard.

![Dashboard for a demo engagement: the authorization card with reference, window, scope and mode, then 12 open findings, a severity chart and report links](docs/dashboard.jpg)

## Safety model

- **One choke point.** Every DNS query, TCP probe and HTTP request goes through `ScopeGuard`. Modules cannot open sockets themselves.
- **Scope is enforced, not advisory.** Targets come from the engagement scope (hosts, `*.wildcards`, IPs, CIDRs, URL origins). Redirects and DNS-resolved IPs are re-checked. Exclusions always win, and refusals are logged.
- **Authorization is recorded.** Each engagement carries an authorization reference, an authorizer and a time window. Outside the window, the guard refuses to send anything.
- **Non-destructive only.** Read-only HTTP methods, a request budget, rate limits and timeouts. There is no exploitation, brute forcing or fuzzing, and no mode enables them.
- **Evidence or it didn't happen.** Each finding links to redacted request/response captures. Cookies and auth headers are scrubbed, and secret-looking values in bodies (`.env` lines, private keys) are masked before anything is written to disk.
- **The dashboard binds to 127.0.0.1 only.** Changing a finding's status requires the token printed at startup.

## Proof it works on a real site

- [**Sample report**](https://htmlpreview.github.io/?https://github.com/sanjeldarshan65-afk/vantage/blob/main/examples/sample-report/report.html): an assessment of my own site, [dragonsmithers.com](https://dragonsmithers.com).
- [**Architecture**](docs/architecture.md): how the scope guard makes every request go through one choke point, and how to write a check module.
- [**Validation write-up**](docs/validation.md): every finding cross-checked against Mozilla HTTP Observatory. That check caught two false positives and a missed clickjacking issue, all now fixed with regression tests.

## Quick start

Requires Node 22 or newer. There are no dependencies to install.

```
node bin/vantage.js demo --serve
```

This starts a deliberately misconfigured lab server on loopback, assesses it, writes reports, and opens the dashboard at http://127.0.0.1:7341. The demo finds 17 issues, including:

- a downloadable `.git` directory and `.env` file
- reflected-origin CORS with credentials
- plain HTTP
- missing security headers
- version disclosure
- weak cookie flags

The lab answers 200 for every unknown path (a "soft 404"), which shows that the checks match content rather than status codes.

## Real engagements

```
node bin/vantage.js init acme-lab \
  --target https://app.acme.example --target "*.acme.example" \
  --auth-ref "SOW-2026-114, signed 2026-11-01" --authorized-by "Jane Doe (CISO)" \
  --ends 2026-12-31 --mode safe
node bin/vantage.js run acme-lab --serve   # live dashboard while it runs
node bin/vantage.js report acme-lab        # rebuild HTML / Markdown / JSON reports
node bin/vantage.js modules                # list checks
```

Edit `data/engagements/<id>/engagement.json` to set exclusions, port policy and rate limits. Modes:

- `passive`: DNS and headers only
- `safe`: all non-destructive checks (the default)
- `full`: adds longer content discovery

## Checks

| Module | What it looks at |
| --- | --- |
| `recon.dns` | A/AAAA/CNAME/MX/NS/SOA records, dangling CNAMEs |
| `recon.email` | SPF, DMARC, and DKIM selector presence |
| `recon.subdomains` | Short in-scope subdomain wordlist, resolved through the guard |
| `recon.ports` | TCP connect scan of about 100 common ports the scope allows; flags exposed databases, remote desktops and the Docker API |
| `web.headers` | HSTS, CSP, framing, MIME sniffing, COOP/COEP/CORP, version disclosure, Subresource Integrity on third-party scripts (meta-tag CSP and referrer policies count) |
| `web.cookies` | Secure, HttpOnly, SameSite, prefixes, overly broad domain |
| `web.cors` | Reflected origins, `null` origin, credentials with wildcards |
| `web.tls` | Plain HTTP; certificate expiry, trust, hostname match, self-signed and key size; TLS 1.0/1.1 still accepted |
| `web.exposure` | Public `.git/`, `.env`, `server-status`, `phpinfo`, `.DS_Store`, directory listing (matched by content, not status) |
| `web.securitytxt` | RFC 9116 `security.txt` present, with Contact and a future Expires date |

Passive mode skips the port scan, legacy-TLS handshakes and path checks.

Every module exports pure `analyze*` helpers that are tested without a network. The rules for adding a module are in [ENGINEERING.md](ENGINEERING.md).

## Reports

`data/engagements/<id>/reports/<timestamp>/` contains:

- `report.html`, the deliverable, printable
- `report.md`
- `report.json`, a stable schema
- `report.sarif`, SARIF 2.1.0 for DefectDojo, GitHub code scanning and other vulnerability trackers

Each report has an executive summary with a risk rating, a severity table, scope, findings with remediation, CWE/OWASP mapping and evidence IDs, methodology, limitations, and a disclaimer. Target-controlled text is HTML-escaped.

## Development

```
npm test        # 89 tests, all on loopback, no internet needed
npm run smoke   # import/instantiation smoke test
```

## Layout

```
bin/vantage.js        CLI
src/core/             scope, guard, rate limits, evidence, audit, store, engine
src/modules/          recon and web checks (auto-discovered)
src/report/           JSON, Markdown, HTML reports
server/ ui/           loopback dashboard (HTTP + SSE, vanilla JS)
examples/             lab target used by the demo and e2e tests
test/                 node:test suites
```

## Legal

See [SECURITY.md](SECURITY.md) for reporting a vulnerability in VANTAGE and the acceptable-use policy.

Use VANTAGE only against systems you own or are explicitly authorized in writing to assess. You are responsible for staying within your authorization.

## License

MIT
