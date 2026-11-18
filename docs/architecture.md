# Architecture

VANTAGE is built around one rule: **a check module cannot reach the network except through the scope guard.** Everything else (rate limits, evidence, the audit trail, the authorization window) hangs off that single choke point, so it cannot be skipped by a module that forgets to call it.

```
 bin/vantage.js ──┐                         ┌── server/ (loopback dashboard, SSE)
                  ▼                         ▼
             ┌─────────┐   ctx    ┌───────────────────┐
             │ Engine  │────────▶ │  check modules    │  recon.* then web.*
             └────┬────┘          └─────────┬─────────┘
                  │                         │ ctx.guard.fetch / tcpProbe / tlsProbe / dns
                  ▼                         ▼
       ┌─────────────────┐        ┌───────────────────────────────────────────┐
       │ EngagementStore │◀───────│ ScopeGuard                                │
       │ findings,assets │ audit  │  1 authorize: scope rules + time window   │
       │ runs, evidence  │ evid.  │  2 RateLimiter: budget, rate, concurrency │
       └─────────────────┘        │  3 http.js / tcp.js / dns.js (the socket) │
                                  │  4 evidence (redacted) + audit record     │
                                  └───────────────────────────────────────────┘
```

## The pieces

| File | Responsibility |
| --- | --- |
| `src/core/scope.js` | Parses scope entries (host, `*.wildcard`, IP, CIDR, URL origin) and answers `matchHost(host, {port, scheme, resolvedIps})`. Exclusions are checked first, then the port allow-list, then targets. Also `withinWindow()` for the authorization dates. Pure: no I/O. |
| `src/core/guard.js` | `ScopeGuard`, the only object that performs network actions. `authorize()` combines scope, DNS resolution (for CIDR rules) and the time window, then writes an allow/deny audit record. `fetch()` re-authorizes **every redirect hop**, so a redirect to an out-of-scope host stops there instead of being followed. |
| `src/core/rate.js` | `RateLimiter`: a hard request budget, a global and per-host token bucket, and a concurrency semaphore. Throttle responses (429/503) back off and retry at most twice. |
| `src/core/http.js`, `tcp.js`, `dns.js` | The actual sockets. Bounded body size and timeouts. Only the guard imports these. |
| `src/core/evidence.js` | Saves a bounded, secret-redacted preview of each request/response and returns an evidence id that findings point to. |
| `src/core/audit.js` | Append-only JSONL of every allow and deny decision, with the module that asked. |
| `src/core/engine.js` | Loads modules from the registry, runs recon then web, gives each module a `ctx`, and enforces a per-module timeout. A module failure is recorded (`failed`, `blocked`, `limited`, `timeout`) and the run continues. |
| `src/core/findings.js` | Normalizes findings and builds the dedupe key (check + target + observed values), so re-running the same engagement updates findings instead of duplicating them. |
| `src/core/store.js` | `EngagementStore` under `data/engagements/<id>/`: engagement, findings, assets, runs, evidence, audit, activity. Triage status (open, fixed, false positive...) survives re-runs. |
| `src/report/` | One JSON report model rendered to Markdown, HTML and SARIF 2.1.0. |
| `server/` | Loopback-only dashboard. Writes need the `x-vantage-token` header; strict CSP; live updates over SSE. |

## Life of a request

Take `web.exposure` asking for `https://acme.example/.env`:

1. The module calls `ctx.guard.fetch(url, { followRedirects: false })`.
2. `authorize()` parses the URL into host, port and scheme and asks `Scope.matchHost()`. If the scope has only a CIDR rule, the host is resolved and its IPs are matched instead. Then the authorization window is checked. Either way an audit record is written.
3. Denied: a `ScopeError` is thrown. The engine marks the module `blocked`, and the refusal shows in the run stats.
4. Allowed: `RateLimiter.acquire()` spends one unit of budget, waits for global and per-host tokens and a concurrency slot. Budget exhausted throws `LimitError`.
5. `requestOnce()` sends the request with a size cap and timeout. The slot is released in a `finally`.
6. If the response is a redirect and redirects are followed, the next hop goes back to step 2.
7. The response is saved as redacted evidence, and the module gets `{status, headers, text, evidence}`.
8. The module decides from **content**, not status codes (`.env` must look like `KEY=value` and not HTML), and calls `ctx.addFinding()` with the evidence id.

## Writing a check module

A module is a plain object; the registry discovers it.

```js
export default {
  id: 'web.example',
  phase: 'web',                 // 'recon' runs before 'web'
  title: 'Example check',
  description: 'What it looks for.',
  defaults: {},
  async run(ctx) {
    if (ctx.options.mode === 'passive') return;      // respect the engagement mode
    const probe = await ctx.openWebTarget();          // cached GET of the target, shared by modules
    if (!probe) return;
    const res = await ctx.guard.fetch(ctx.helpers.joinUrl(probe.url, '/thing'));
    if (res.status === 200 && /signature/.test(res.text)) {
      await ctx.addFinding({
        check: 'web.example.found', title: 'Thing is exposed', severity: 'low',
        target: res.url, evidence: [res.evidence.id],
        description: '...', impact: '...', remediation: '...'
      });
    }
  }
};
```

Rules a module should follow:

- **Never import `node:http`, `node:net`, `node:tls` or `node:dns`.** Use `ctx.guard`. That's the whole safety model.
- **Re-throw `ScopeError` and `LimitError`.** Swallowing them hides a refusal or keeps spending a budget that's gone.
- **Prove findings with content.** Soft-404 sites return 200 for everything; the lab target does this on purpose.
- **Keep the decision logic in a pure exported function** (`analyzeHeaders`, `matchExposure`, `analyzeCertificate`) and unit-test it without a network.

## Design decisions

- **One choke point, not a convention.** Each module could check scope itself; one would eventually forget. Making the guard the only owner of sockets turns a convention into a structural guarantee, testable by a single grep.
- **Re-authorize every redirect hop.** An in-scope page that redirects off-scope is common (login providers, CDNs). Following it would test a system nobody authorized.
- **DNS policy records follow their owner.** `_dmarc.acme.example` is judged as `acme.example`, but for DNS lookups only. HTTP or TCP to that name still needs its own scope rule.
- **Evidence is redacted at write time.** A report can be shared without leaking the secrets it found; the key names stay so the finding is still provable.
- **Findings dedupe across runs.** Triage is the expensive human step; re-running must not reset it.
- **Fail one module, not the run.** A timeout in TLS probing shouldn't lose the header findings.

## Known limits

See [validation.md](validation.md#known-gaps). Briefly: no injection testing (by design: it is a misconfiguration scanner and stays non-destructive), legacy TLS detection depends on the local OpenSSL, and the HTTP→HTTPS redirect check needs port 80 in scope.
