# VANTAGE — engineering contract

VANTAGE is an **authorized security assessment workbench**: recon + non-destructive web
configuration checks + evidence capture + reports + local dashboard. It is for assets the operator
owns or is explicitly authorized to test. Every network action passes one choke point.

Read this file before writing code. The interfaces below are frozen; if you need a change, message
the Lead instead of editing someone else's files.

## Non-negotiable safety rules

1. **One choke point.** No module may call `fetch`, `http.request`, `https.request`, `net.connect`,
   `dns.*` directly. Use `ctx.guard` / `ctx.http` / `ctx.dns`. Tests may open local servers.
2. **Non-destructive only.** Allowed: DNS queries, TCP connect scan, TLS handshake, HTTP GET/HEAD/
   OPTIONS/POST-to-harmless-endpoint, reading banners. Forbidden: exploitation, brute force,
   fuzzing at volume, destructive methods (PUT/DELETE to real paths), DoS, credential attacks,
   writing files to a target, shell commands on targets.
3. **Scope is authoritative.** Every target comes from the engagement scope. Refusals are audited,
   never silently retried elsewhere.
4. **Evidence or it didn't happen.** A finding that claims an HTTP observation must reference an
   `evidenceId` produced by `ctx.guard.fetch()`.
5. **No new npm dependencies.** Node 24 built-ins only (`node:http`, `node:https`, `node:tls`,
   `node:net`, `node:dns/promises`, `node:crypto`, `node:zlib`, `node:url`, `node:path`,
   `node:fs/promises`, `node:test`, `node:assert`). The repo has no build step; ESM everywhere.
6. **Tests never touch the network.** Use `node:test` with local `node:http` servers on
   `127.0.0.1:0`. If a module needs a live host, split it into `collect*()` (network) and
   `analyze*()` (pure) and test the pure half.

## Layout and ownership

```
vantage/
  bin/vantage.js                 CLI                      [Lead]
  src/core/                      engine primitives        [Lead]
  src/modules/recon/*.js         recon checks             [recon teammate]
  src/modules/web/*.js           web config checks        [web teammate]
  src/report/*.js                MD/HTML/JSON reports     [report teammate]
  server/*.js                    dashboard HTTP+SSE API   [dashboard teammate]
  ui/*                           static dashboard (no build) [dashboard teammate]
  test/*.test.js                 tests (unique filenames per owner)
  examples/                      lab target fixture + demo engagement [Lead]
  ENGINEERING.md                 this file
  README.md                      product docs             [Lead]
```

Do not edit files outside your scope. Add tests as `vantage/test/<your-area>-<topic>.test.js`.

## Engagement on disk

`vantage/data/engagements/<engagementId>/`

| file | format | notes |
| --- | --- | --- |
| `engagement.json` | JSON | `{ engagement, scope, options }` — see below |
| `audit.jsonl` | JSONL append | every allowed/denied network action |
| `evidence.jsonl` | JSONL append | redacted request/response captures |
| `findings.json` | JSON array | latest-wins, atomic rewrite |
| `assets.json` | JSON array | latest-wins, atomic rewrite |
| `activity.jsonl` | JSONL append | human-readable progress feed |
| `runs/<runId>.json` | JSON | one assessment run record |
| `reports/<stamp>/` | files | `report.json`, `report.md`, `report.html` |

`engagement.json`:

```json
{
  "engagement": {
    "id": "acme-lab",
    "name": "ACME Lab",
    "client": "ACME Corp",
    "authorizedBy": "Jane Doe (CISO)",
    "authorizationRef": "SOW-2026-114, signed 2026-11-01",
    "startsAt": "2026-11-01T00:00:00.000Z",
    "endsAt": "2026-12-31T00:00:00.000Z",
    "mode": "safe",
    "notes": "Lab only."
  },
  "scope": {
    "targets": ["http://127.0.0.1:8080", "*.acme.example"],
    "exclude": [],
    "ports": { "include": null, "exclude": [] },
    "limits": {
      "requestsPerSecond": 5, "perHostRequestsPerSecond": 3, "concurrency": 4,
      "maxRequests": 2000, "timeoutMs": 8000, "maxResponseBytes": 262144,
      "maxEvidenceBytes": 4096
    },
    "allowThirdParty": false
  },
  "options": { "ports": "top100", "paths": "safe", "subdomains": "short" }
}
```

Scope entry grammar: hostname (`app.acme.example`), wildcard (`*.acme.example`, subdomains only,
never the apex, suffix must have ≥2 labels), IPv4/IPv6 literal, CIDR (not /0), or URL origin
(`https://app.acme.example:8443`, constrains scheme+host+port). `exclude` uses the same grammar and
always wins. Hostnames are additionally matched by their resolved IPs against IP/CIDR entries.

Modes: `passive` (DNS/headers only), `safe` (default; full non-destructive checks), `full`
(adds the long content-discovery list). No mode enables exploitation.

## Module contract

One default export per file in `src/modules/{recon,web}/`. The registry auto-discovers them.

```js
export default {
  id: 'web.headers',            // '<phase>.<slug>', unique, stable, used as finding.check prefix
  phase: 'web',                 // 'recon' | 'web'
  title: 'HTTP security headers',
  description: 'Grades HSTS, CSP, clickjacking, MIME-sniffing and disclosure headers.',
  defaults: { timeoutMs: 8000 },   // merged into ctx.options.module
  async run(ctx) { /* ... */ }
};
```

`ctx` (created by the engine; never construct it yourself):

| member | type | notes |
| --- | --- | --- |
| `ctx.engagement` | object | normalized engagement record |
| `ctx.scope` | `Scope` | `.matchHost()`, `.allowedPort()` |
| `ctx.guard` | `ScopeGuard` | `fetch()`, `dnsLookup()`, `authorize()`, `.stats()` |
| `ctx.http` | `GuardHttpClient` | low-level; prefer `ctx.guard.fetch()` |
| `ctx.dns` | `GuardDns` | `lookup()`, `resolve()`, `resolveTxt()`, `resolveCname()`, `resolveMx()`, `resolveNs()` |
| `ctx.store` | `EngagementStore` | read/write findings, assets, notes |
| `ctx.addFinding(partial)` | function | normalizes + dedupes + persists, returns finding |
| `ctx.addAsset(partial)` | function | normalizes + dedupes + persists, returns asset |
| `ctx.note(message, data?)` | function | append to activity feed |
| `ctx.target` | object | `{ host, url, scheme, port }` — the run target |
| `ctx.options` | object | `{ module: {...}, engagement: {...}, mode }` |
| `ctx.logger` | child logger | `debug/info/warn/error` |
| `ctx.signal` | AbortSignal | aborted on run cancel / budget exhaustion |

`run()` returns nothing; findings/assets are contributed through `ctx`. Returning
`{ notes: string[] }` is allowed. Throw to fail the module (engine records the error, continues).

Example:

```js
export default {
  id: 'web.cookies',
  phase: 'web',
  title: 'Cookie flags',
  async run(ctx) {
    const res = await ctx.guard.fetch(ctx.target.url);
    for (const raw of res.response.setCookie ?? []) {
      const cookie = analyzeSetCookie(raw);           // pure helper in the same file
      if (!cookie.secure) {
        ctx.addFinding({
          check: 'web.cookies.missing-secure',
          title: `Cookie "${cookie.name}" set without Secure`,
          severity: 'low',
          confidence: 'confirmed',
          target: ctx.target.url,
          evidence: [res.evidence.id],
          observed: [{ key: 'set-cookie', value: raw }],
          description: '...', impact: '...', remediation: '...',
          references: ['https://owasp.org/...'], cwe: ['CWE-614'], owasp: ['A05:2021']
        });
      }
    }
  }
};
```

## Finding schema (normalized by `ctx.addFinding` / `store.addFinding`)

```js
{
  id: 'fnd_…',                 // generated
  engagementId, runId,
  check: 'web.headers.missing-hsts',
  title: 'HSTS not enabled',
  severity: 'critical|high|medium|low|info',
  confidence: 'confirmed|likely|possible',
  poe: 'observed|verified',    // observed = seen once; verified = reproduced/retested
  status: 'open|fixed|accepted|false_positive|not_observed',
  target: 'https://acme.example/',
  assetId: 'ast_…|null',
  description, impact, remediation,
  observed: [{ key, value }],
  evidence: ['ev_…'],
  references: ['https://…'],
  cwe: ['CWE-693'], owasp: ['A05:2021'],
  firstSeen, lastSeen, occurrences,
  history: [{ ts, actor, event, from, to, note }]
}
```

Modules contribute `{ check, title, severity, confidence?, description, impact?, remediation,
target?, asset?, observed?, evidence?, references?, cwe?, owasp?, poe? }` and the engine fills the
rest. Dedupe key = `check + '|' + target + '|' + observed`. Re-reporting an existing finding bumps
`lastSeen`/`occurrences` and merges evidence instead of creating a duplicate.

## Asset schema

```js
{ id: 'ast_…', engagementId, type: 'domain|subdomain|ip|service|endpoint',
  value: 'app.acme.example', parentId: 'ast_…|null',
  attributes: { product: 'nginx', version: '1.24', port: 443, protocol: 'tcp' },
  state: 'tested|untested', firstSeen, lastSeen }
```

Dedupe by `type + '|' + value`. `ctx.addAsset({ type, value, parent?, attributes? })` normalizes.
Modules must register what they discover (IPs, services, endpoints) so coverage is honest.

## Report interface (`src/report/index.js`)

```js
export async function writeReports(store, options) // -> { jsonPath, markdownPath, htmlPath, dir }
export function buildReport(store)                 // -> { json, markdown, html } strings
```

`buildReport` must be pure over the store snapshot (`store.snapshot()`), so the report teammate can
test with fixture objects. Reports: executive summary, severity table, coverage, findings with
evidence excerpt, methodology, engagement authorization block, limitations, disclaimer.

## Dashboard interface (`server/`)

`createServer({ dataDir, token, logger })` → `{ server, start(port), close(), url }`. Bind
`127.0.0.1` only. Mutating routes require the `x-vantage-token` header (token printed by CLI).
Read-only API:

```
GET /api/engagements                     -> [{id,name,client,counts,lastRun}]
GET /api/engagements/:id                 -> engagement.json + counts + coverage
GET /api/engagements/:id/findings        -> { findings }
GET /api/engagements/:id/assets          -> { assets }
GET /api/engagements/:id/runs            -> [{ id, startedAt, status, stats }]
GET /api/engagements/:id/evidence/:evId  -> redacted capture
GET /api/engagements/:id/report?format=json|md|html
PATCH /api/engagements/:id/findings/:fid -> { status, note }   (token required)
GET /api/events                          -> SSE progress stream
```

Static UI served from `ui/` at `/`. Vanilla ESM + CSS, no framework, no build step, dark theme.

## Coding standards

- ESM, 2-space indent, single quotes, semicolons, `const` by default.
- Every exported function gets a short JSDoc block with `@param`/`@returns` when non-obvious.
- Validate inputs; never trust target responses (they are attacker-controlled data).
- Never `console.log` in modules — use `ctx.logger`.
- Bound everything: timeouts, response size (use `fetch` defaults), concurrency (`ctx.guard`
  enforces), loop counts.
- Errors from the network layer are expected: catch, log at debug, degrade gracefully. A module
  must not throw for a target being down; throw only for programmer errors.
- Before declaring done: `node --test vantage/test/<your-files>` passes, and
  `node --check` / import smoke test of every file you touched succeeds.

## Definition of done for a module

1. Registered automatically (default export, correct `id`/`phase`).
2. Findings include evidence ids, remediation text, CWE/OWASP where sensible.
3. Assets registered for every host/IP/service/endpoint discovered.
4. Pure analysis helpers exported for tests (e.g. `analyzeHeaders`, `analyzeSetCookie`).
5. Tests cover: positive detection, negative (clean target), and a malformed/absent response.
6. No direct network calls outside `ctx.guard`/`ctx.http`/`ctx.dns`.
7. Run `node vantage/scripts/smoke.mjs` once; it must end with `SMOKE OK` before you start.

## Core API appendix (implementation truth)

These are the exact shapes the core already returns. Trust this over guesswork.

`await ctx.guard.fetch(url, opts)` → object:

```js
{
  url, status, statusText, ok,
  request: { method, url, headers },
  response: {
    status, statusText, headers,   // headers: lowercased names, string | string[]
    setCookie: string[],           // raw Set-Cookie values
    body: Buffer, bytes, receivedBytes, truncated, elapsedMs,
    remoteAddress, httpVersion,
    tls: { protocol, cipher: {name, version}, authorized, authorizationError,
           cert: { subject, issuer, validFrom, validTo, serialNumber, fingerprint256,
                   subjectAltName, keyType, keyBits, selfSigned, isCA, hostnameMatch } | null } | null
  },
  redirects: [{ url, status, location }],
  redirectsBlocked: { url, reason } | null,
  evidence: { id, sha256, ... },   // pass evidence.id into findings
  text,                            // getter, utf8 body
  header(name)                     // case-insensitive header helper
}
```

The response headers are the raw server output — treat them as untrusted data.

`await ctx.guard.tcpProbe(host, port, { timeoutMs, bannerBytes })` →
`{ host, port, open, elapsedMs, banner, error, evidenceId }`

`await ctx.guard.tlsProbe(host, port, { timeoutMs, servername, minVersion, maxVersion })` →
`{ host, port, open, elapsedMs, tls, error, evidenceId }` where `tls` is the same shape as
`response.tls` above. Probe TLS 1.0/1.1 by passing `minVersion: 'TLSv1', maxVersion: 'TLSv1'`
etc.; an `open: false` with `error` means that version is refused.

`await ctx.dns.resolveTxt(host)` → `{ host, rrtype, records: string[], elapsedMs, error, evidenceId }`.
Other helpers: `lookup` → `{ addresses, families }`, `resolve4/6`, `resolveCname`, `resolveMx`,
`resolveNs`, `resolveSoa`, `reverse`, `query(host, rrtype)`.

`await ctx.openWebTarget()` → `{ url, scheme, port, status, headers, setCookie, body, text, session }`
or `null` when nothing answers. Cached per run: call it freely from every web module. `url` is the
origin (no path). Use `ctx.helpers.joinUrl(probe.url, '/path')` to build URLs.

`ctx.guard.stats()` → `{ requests, denials, remaining }` (remaining request budget).
`ctx.guard.limiter.budget.remaining` is also available for budget-aware loops.

Report entry points:

```js
await buildReport(storeOrSnapshot)  // -> { json, markdown, html } strings
await writeReports(store, { outDir }) // -> { dir, jsonPath, markdownPath, htmlPath }
```

`writeReports` receives a live `EngagementStore` (so it can resolve `store.evidence.get(id)` for
linked evidence ids); `buildReport` also accepts a plain snapshot object for tests.

