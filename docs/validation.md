# Validation against a real site

Lab targets show that the checks fire. A real site shows whether they're *right*. On 18 November 2026 I ran VANTAGE against my own site, [dragonsmithers.com](https://dragonsmithers.com), a static site on GitHub Pages. I then compared every finding with the raw HTTP responses and with [Mozilla HTTP Observatory](https://developer.mozilla.org/en-US/observatory/analyze?host=dragonsmithers.com), an independent and widely used grader. Observatory scored the site B (75/100).

- Scope was the single origin `https://dragonsmithers.com`, in `safe` mode: 13 requests, with the port scan pinned to 443 by scope.
- The published report is in [`examples/sample-report/`](../examples/sample-report/).

## What the comparison caught

The first run produced two false positives and missed one real issue. All three are fixed and covered by regression tests in `test/modules.test.js`.

| Bug | Kind | Cause | Fix |
| --- | --- | --- | --- |
| "Content-Security-Policy header is missing" | False positive | The site sets a strict CSP with `<meta http-equiv>`, and only response headers were read. | Meta policies are now parsed and graded. VANTAGE reports an *info* note that meta CSP cannot carry `frame-ancestors`. |
| "Referrer-Policy header is missing" | False positive | The site uses `<meta name="referrer">`. Observatory passed it and VANTAGE didn't. | Meta referrer policies now count. Unsafe values are still flagged. |
| Clickjacking not reported | **False negative** | The rule only fired when a CSP header existed, so a page with *no* CSP header and *no* X-Frame-Options, the worst case, was never reported. Observatory's largest deduction (−20) was exactly this. | The rule now fires whenever neither X-Frame-Options nor a header `frame-ancestors` is present. |

Two more bugs surfaced on the way, and only a real remote target could expose them:

- **CLI runs against real sites quit silently halfway through.** The rate limiter's refill timer was `unref()`'d. Once a module used up the per-host allowance, the process had nothing keeping it alive and exited with code 0. The lab demo never showed it, because its own server kept the process running. Fixed, with a child-process regression test (`test/core-rate-keepalive.test.js`) that fails without the fix.
- **DMARC/DKIM lookups were refused by scope.** `_dmarc.example.com` isn't literally the in-scope host. DNS-only lookups of underscore policy records are now judged against the owning domain. HTTP and TCP to those names stay out of scope (`test/core-guard-dns-policy.test.js`).

## Final comparison

| Area | VANTAGE | Observatory | Agree? |
| --- | --- | --- | --- |
| Framing / clickjacking | medium: not protected | fail (−20) | Yes |
| X-Content-Type-Options | low: missing | fail (−5) | Yes |
| Content-Security-Policy | info: meta tag only, strict policy | pass (+5) | Yes |
| Referrer-Policy | no finding (meta policy present) | pass (+5) | Yes |
| HSTS | low: no `includeSubDomains` | pass (max-age ≥ 6 months) | VANTAGE is stricter |
| COOP / CORP / COEP | low / info: missing | 0-point results | Yes (informational) |
| CORS `Access-Control-Allow-Origin: *` | info | not scored | Yes, after downgrading from *low* (public static content) |
| security.txt | info: missing | not checked | VANTAGE only |
| Subresource Integrity | not checked | fail (0 points) | Gap in VANTAGE |
| HTTP → HTTPS redirect | not verified: port 80 was out of scope | pass | Scope choice, not a miss |

## Known gaps

- **No Subresource Integrity check yet.** Observatory has one.
- **Legacy TLS** (1.0/1.1) detection relies on the local OpenSSL being willing to offer those versions. It can miss a server that accepts them, but it can't falsely report one.
- **The HTTP→HTTPS redirect check** needs `http://` or the bare host in scope. A single `https://` origin deliberately excludes port 80.
