# dragonsmithers.com — Security Assessment Report

| Field | Value |
| --- | --- |
| Client | Darshan Sanjel (site owner) |
| Engagement | \`dragonsmithers\` |
| Assessment mode | \`safe\` |
| Authorization reference | \*\*Owner-approved self-assessment of own site, 2026-11-18\*\* |
| Authorized by | Darshan Sanjel, site owner |
| Assessment window | 2026-11-18 18:12 UTC → 2026-11-30 00:00 UTC |
| Report generated | 2026-11-18 18:12 UTC |
| Report schema | \`1\` (tool VANTAGE 1.0.0) |

## Authorization notice

> This report describes a **non-destructive** security assessment of assets authorized in writing under **Owner-approved self-assessment of own site, 2026-11-18** by **Darshan Sanjel, site owner**. Testing was limited to the assets, time window and check set recorded in this engagement. VANTAGE performs no exploitation, no brute force, no fuzzing at volume and no denial-of-service testing. Do not act on this report outside the recorded authorization.

## Table of contents

1. [Executive summary](#executive-summary)
2. [Severity summary](#severity-summary)
3. [Status summary](#status-summary)
4. [Scope and methodology](#scope-and-methodology)
5. [Findings](#findings)
6. [Coverage](#coverage)
7. [Asset inventory](#asset-inventory)
8. [Assessment runs](#assessment-runs)
9. [Audit summary](#audit-summary)
10. [Limitations](#limitations)
11. [Disclaimer](#disclaimer)

## Executive summary

**Overall risk rating: Medium** (active risk score 6).

VANTAGE performed a non-destructive security assessment of **dragonsmithers.com** for **Darshan Sanjel (site owner)** across 1 authorized target in `safe` mode.

1 assessment run is recorded. Together they produced 10 findings across 3 assets (3 tested, 0 untested).

10 findings remain active; 0 are closed as fixed or false positive. Active by severity: critical 0, high 0, medium 1, low 3, info 6. The rating follows from these active counts and the weighted risk score, not from closed findings.

The highest-severity active finding is **Response is not protected against clickjacking** (MEDIUM) at `https://dragonsmithers.com`.

Remediation should follow severity order, starting with critical and high findings. Re-testing after remediation is recommended to confirm each finding no longer reproduces.

## Severity summary

| Severity | Findings | Share |
| --- | ---: | ---: |
| **Critical** | 0 | 0% |
| **High** | 0 | 0% |
| **Medium** | 1 | 10% |
| **Low** | 3 | 30% |
| **Info** | 6 | 60% |
| **Total** | **10** | 100% |

_Shares are rounded. The risk rating is derived from active findings (all statuses except fixed and false positive) using the severity weights critical 10, high 6, medium 3, low 1, info 0._

## Status summary

| Status | Findings |
| --- | ---: |
| Open | 10 |
| Fixed | 0 |
| Accepted | 0 |
| False positive | 0 |
| Not observed | 0 |
| **Total** | **10** |

## Scope and methodology

### Authorized scope

- **Assessment mode:** `safe`
- **Authorized targets:**
  - `https://dragonsmithers.com:443`
- **Exclusions:** none
- **Port rules:** any port not excluded by policy
- **Rate limits and budgets:** global request rate 5; per-host request rate 3; concurrency 4; request budget 2000; request timeout 8000 ms; max response size 256.0 KiB; max evidence capture size 4.0 KiB
- **Third-party endpoints:** not permitted

### Methodology

Safe mode: the full non-destructive check set was enabled — DNS records, TLS configuration, TCP service identification, HTTP security configuration and bounded content discovery.

1. **Scope enforcement** — Every network action was authorized against the engagement scope before it ran. Out-of-scope or excluded requests were refused and recorded in the audit log rather than retried elsewhere.
2. **Reconnaissance** — DNS records, TLS configuration, exposed TCP services and (in scope) hostnames and endpoints were enumerated only for assets covered by the authorized scope.
3. **Configuration review** — Responses were graded against the enabled check set: HTTP security headers, cookie attributes, CORS policy, allowed methods and other non-destructive configuration signals.
4. **Evidence capture** — HTTP exchanges were stored as redacted, content-hashed evidence records. Findings reference those records by identifier; authorization headers, cookies and credential query parameters are redacted.
5. **Analysis** — Findings were normalized against a fixed severity, confidence and proof-of-evidence vocabulary. Re-observations merge into the existing finding instead of creating duplicates.

**Checks executed (10):** `recon.dns`, `recon.email`, `recon.ports`, `recon.subdomains`, `web.cookies`, `web.cors`, `web.exposure`, `web.headers`, `web.securitytxt`, `web.tls`

Every network action was authorized through the scope guard. Refusals are recorded in the audit trail, and evidence records are redacted for secrets and truncated to a bounded preview.

## Findings

Findings are ordered by severity (critical first) and then by title. 10 findings recorded; 10 currently active.

### Finding 1: Response is not protected against clickjacking

**Severity: MEDIUM** · **Confidence:** `confirmed` · **Status:** `open` · **Proof of evidence:** `observed`

| Attribute | Value |
| --- | --- |
| Target | https://dragonsmithers.com |
| Check | `web.headers.missing-frame-protection` |
| Finding id | `fnd_be9e70607697` |
| First observed | 2026-11-18 18:12 UTC |
| Last observed | 2026-11-18 18:12 UTC |
| Occurrences | 1 |
| CWE | CWE-1021 |
| OWASP | A05:2021 |

**Description**

Neither an \`X-Frame-Options\` header nor a CSP \`frame-ancestors\` directive is set, so the page can be embedded in a frame on any site.

**Impact**

An attacker can overlay the application in an invisible frame and trick a signed-in user into clicking destructive or sensitive actions (clickjacking).

**Remediation**

Set \`Content-Security-Policy: frame-ancestors 'none'\` (or \`'self'\` if framing is required). Keep \`X-Frame-Options: DENY\` as a fallback for older browsers.

**Observed**

| Key | Value |
| --- | --- |
| x-frame-options | absent |
| csp-frame-ancestors | absent |

**Evidence**

- `ev_ecb255dc94f5`

**References**

- https://owasp.org/www-project-secure-headers/#x-frame-options
- https://owasp.org/www-community/attacks/Clickjacking

### Finding 2: Cross-Origin-Opener-Policy (COOP) header is missing

**Severity: LOW** · **Confidence:** `confirmed` · **Status:** `open` · **Proof of evidence:** `observed`

| Attribute | Value |
| --- | --- |
| Target | https://dragonsmithers.com |
| Check | `web.headers.missing-coop` |
| Finding id | `fnd_8b90ffe47510` |
| First observed | 2026-11-18 18:12 UTC |
| Last observed | 2026-11-18 18:12 UTC |
| Occurrences | 1 |
| CWE | CWE-693 |
| OWASP | A05:2021 |

**Description**

The response does not set \`Cross-Origin-Opener-Policy\`, so a cross-origin window that opens this document keeps a reference to it.

**Impact**

Cross-window scripting (XS-Leaks, Spectre-style side channels and window.opener abuse) is easier when the opener relationship is preserved.

**Remediation**

Set \`Cross-Origin-Opener-Policy: same-origin\` on HTML responses.

**Observed**

| Key | Value |
| --- | --- |
| cross-origin-opener-policy | absent |

**Evidence**

- `ev_ecb255dc94f5`

**References**

- https://owasp.org/www-project-secure-headers/#cross-origin-opener-policy

### Finding 3: HSTS policy does not cover subdomains

**Severity: LOW** · **Confidence:** `confirmed` · **Status:** `open` · **Proof of evidence:** `observed`

| Attribute | Value |
| --- | --- |
| Target | https://dragonsmithers.com |
| Check | `web.headers.hsts-missing-include-subdomains` |
| Finding id | `fnd_3be797923562` |
| First observed | 2026-11-18 18:12 UTC |
| Last observed | 2026-11-18 18:12 UTC |
| Occurrences | 1 |
| CWE | CWE-319 |
| OWASP | A02:2021 |

**Description**

The Strict-Transport-Security header does not include the \`includeSubDomains\` directive, so the policy only protects the exact host that sent it.

**Impact**

HTTP-only subdomains (staging, legacy portals, mail front-ends) remain reachable over cleartext and can be used to steal cookies scoped to the parent domain.

**Remediation**

Add \`includeSubDomains\` to the header once every subdomain serves HTTPS: \`Strict-Transport-Security: max-age=31536000; includeSubDomains\`.

**Observed**

| Key | Value |
| --- | --- |
| strict-transport-security | max-age=31556952 |

**Evidence**

- `ev_ecb255dc94f5`

**References**

- https://owasp.org/www-project-secure-headers/#strict-transport-security

### Finding 4: X-Content-Type-Options header is missing

**Severity: LOW** · **Confidence:** `confirmed` · **Status:** `open` · **Proof of evidence:** `observed`

| Attribute | Value |
| --- | --- |
| Target | https://dragonsmithers.com |
| Check | `web.headers.missing-x-content-type-options` |
| Finding id | `fnd_cec97186e43e` |
| First observed | 2026-11-18 18:12 UTC |
| Last observed | 2026-11-18 18:12 UTC |
| Occurrences | 1 |
| CWE | CWE-16 |
| OWASP | A05:2021 |

**Description**

The response does not set \`X-Content-Type-Options: nosniff\`, so some browsers will sniff a body and execute it as a type the server did not declare.

**Impact**

A user-uploaded file that is served back with a permissive content type can be interpreted as HTML or script, turning a file upload into stored XSS.

**Remediation**

Set \`X-Content-Type-Options: nosniff\` on every response (it is cheap and safe to apply globally).

**Observed**

| Key | Value |
| --- | --- |
| x-content-type-options | absent |

**Evidence**

- `ev_ecb255dc94f5`

**References**

- https://owasp.org/www-project-secure-headers/#x-content-type-options

### Finding 5: Content-Security-Policy is set with a meta tag only

**Severity: INFO** · **Confidence:** `confirmed` · **Status:** `open` · **Proof of evidence:** `observed`

| Attribute | Value |
| --- | --- |
| Target | https://dragonsmithers.com |
| Check | `web.headers.csp-meta-only` |
| Finding id | `fnd_d4f63cf97dc8` |
| First observed | 2026-11-18 18:12 UTC |
| Last observed | 2026-11-18 18:12 UTC |
| Occurrences | 1 |
| CWE | CWE-693 |
| OWASP | A05:2021 |

**Description**

The page declares its CSP in a &lt;meta http-equiv&gt; tag instead of a response header. Browsers enforce its fetch directives, but ignore frame-ancestors, sandbox and report-uri/report-to in a meta policy.

**Impact**

Framing control and violation reporting are unavailable; the policy also only starts applying once the tag is parsed.

**Remediation**

Where the host allows it, send the policy as a Content-Security-Policy response header. On hosts that cannot set headers (for example GitHub Pages), put the site behind a CDN that can, such as Cloudflare.

**Observed**

| Key | Value |
| --- | --- |
| meta content-security-policy | default-src 'self'; script-src 'self' https://static.cloudflareinsights.com; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://cloudflareinsights.com; form-action 'self'; base-uri 'self'; object-src 'none'; frame-src 'none'; upgrade-insecure-requests |

**Evidence**

- `ev_ecb255dc94f5`

**References**

- https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta#http-equiv

### Finding 6: CORS wildcard origin policy is enabled

**Severity: INFO** · **Confidence:** `confirmed` · **Status:** `open` · **Proof of evidence:** `observed`

| Attribute | Value |
| --- | --- |
| Target | https://dragonsmithers.com |
| Check | `web.cors.wildcard-origin` |
| Finding id | `fnd_610e443a77af` |
| First observed | 2026-11-18 18:12 UTC |
| Last observed | 2026-11-18 18:12 UTC |
| Occurrences | 1 |
| CWE | CWE-942 |
| OWASP | A05:2021 |

**Description**

The endpoint returns \`Access-Control-Allow-Origin: \*\`, so any origin can read its responses. No credentials are shared, so this is only a problem if the response contains data that should not be world-readable.

**Impact**

Any website can fetch and read this resource on behalf of the visitor (including intranet-only data reachable through the visitor's network position).

**Remediation**

If the data is truly public this is acceptable — document it. Otherwise replace the wildcard with an exact origin allow-list and drop \`Access-Control-Allow-Credentials\` from responses that do not need it.

**Observed**

| Key | Value |
| --- | --- |
| access-control-allow-origin | \* |
| access-control-allow-credentials | false |
| responses | GET, Origin: null GET |

**Evidence**

- `ev_92892c4570f3`
- `ev_ba08e8a9fe82`

**References**

- https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- https://portswigger.net/web-security/cors

### Finding 7: Cross-Origin-Embedder-Policy (COEP) header is missing

**Severity: INFO** · **Confidence:** `confirmed` · **Status:** `open` · **Proof of evidence:** `observed`

| Attribute | Value |
| --- | --- |
| Target | https://dragonsmithers.com |
| Check | `web.headers.missing-coep` |
| Finding id | `fnd_74172d2c237d` |
| First observed | 2026-11-18 18:12 UTC |
| Last observed | 2026-11-18 18:12 UTC |
| Occurrences | 1 |
| CWE | CWE-693 |
| OWASP | A05:2021 |

**Description**

The response does not set \`Cross-Origin-Embedder-Policy\`. Without COEP the page is not cross-origin isolated, so powerful isolation-based mitigations are unavailable.

**Impact**

Some browser hardening features (high-precision timers, SharedArrayBuffer) are unavailable and cross-origin reads are less constrained.

**Remediation**

Set \`Cross-Origin-Embedder-Policy: require-corp\` once embedded resources opt in via CORP.

**Observed**

| Key | Value |
| --- | --- |
| cross-origin-embedder-policy | absent |

**Evidence**

- `ev_ecb255dc94f5`

**References**

- https://owasp.org/www-project-secure-headers/#cross-origin-embedder-policy

### Finding 8: Cross-Origin-Resource-Policy (CORP) header is missing

**Severity: INFO** · **Confidence:** `confirmed` · **Status:** `open` · **Proof of evidence:** `observed`

| Attribute | Value |
| --- | --- |
| Target | https://dragonsmithers.com |
| Check | `web.headers.missing-corp` |
| Finding id | `fnd_d873e3243627` |
| First observed | 2026-11-18 18:12 UTC |
| Last observed | 2026-11-18 18:12 UTC |
| Occurrences | 1 |
| CWE | CWE-693 |
| OWASP | A05:2021 |

**Description**

The response does not declare a \`Cross-Origin-Resource-Policy\`, so it can be embedded cross-origin.

**Impact**

Third-party pages can load the resource in no-cors mode, easing cross-origin data probing (e.g. XS-Leaks).

**Remediation**

Set \`Cross-Origin-Resource-Policy: same-origin\` (or \`same-site\` where needed) on sensitive responses.

**Observed**

| Key | Value |
| --- | --- |
| cross-origin-resource-policy | absent |

**Evidence**

- `ev_ecb255dc94f5`

**References**

- https://owasp.org/www-project-secure-headers/#cross-origin-resource-policy

### Finding 9: No security.txt file

**Severity: INFO** · **Confidence:** `confirmed` · **Status:** `open` · **Proof of evidence:** `observed`

| Attribute | Value |
| --- | --- |
| Target | https://dragonsmithers.com/.well-known/security.txt |
| Check | `web.securitytxt.missing` |
| Finding id | `fnd_d4a1c620c069` |
| First observed | 2026-11-18 18:12 UTC |
| Last observed | 2026-11-18 18:12 UTC |
| Occurrences | 1 |
| CWE | — |
| OWASP | — |

**Description**

There is no /.well-known/security.txt telling researchers how to report a vulnerability.

**Impact**

People who find a problem may not report it, or may report it publicly.

**Remediation**

Publish /.well-known/security.txt with at least Contact and Expires fields (securitytxt.org can generate one).

**Observed**

| Key | Value |
| --- | --- |
| status | 404 |

**Evidence**

- `ev_638d2dab7547`

**References**

- https://www.rfc-editor.org/rfc/rfc9116

### Finding 10: Permissions-Policy header is missing

**Severity: INFO** · **Confidence:** `confirmed` · **Status:** `open` · **Proof of evidence:** `observed`

| Attribute | Value |
| --- | --- |
| Target | https://dragonsmithers.com |
| Check | `web.headers.missing-permissions-policy` |
| Finding id | `fnd_25146599f71e` |
| First observed | 2026-11-18 18:12 UTC |
| Last observed | 2026-11-18 18:12 UTC |
| Occurrences | 1 |
| CWE | CWE-693 |
| OWASP | A05:2021 |

**Description**

The response does not restrict powerful browser features. Without a policy, embedded third-party frames and compromised scripts can request camera, microphone, geolocation and similar access.

**Impact**

Feature access is granted by default to any origin the page embeds, increasing blast radius.

**Remediation**

Set \`Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()\` and re-enable only the features the application actually uses.

**Observed**

| Key | Value |
| --- | --- |
| permissions-policy | absent |

**Evidence**

- `ev_ecb255dc94f5`

**References**

- https://owasp.org/www-project-secure-headers/#permissions-policy

## Coverage

Coverage counts the assets registered by the checks and whether each one was tested. Untested assets are a known gap, not a clean result.

| Asset type | Total | Tested | Untested | Tested % |
| --- | ---: | ---: | ---: | ---: |
| domain | 1 | 1 | 0 | 100% |
| subdomain | 0 | 0 | 0 | 0% |
| ip | 0 | 0 | 0 | 0% |
| service | 1 | 1 | 0 | 100% |
| endpoint | 1 | 1 | 0 | 100% |
| **Total** | **3** | **3** | **0** | **100%** |

_Every recorded asset was tested at least once._

## Asset inventory

| # | Type | Value | State | Attributes |
| ---: | --- | --- | --- | --- |
| 1 | domain | `dragonsmithers.com` | tested | — |
| 2 | service | `dragonsmithers.com:443` | tested | banner=, port=443, protocol=tcp, tls=TLSv1.3 |
| 3 | endpoint | `https://dragonsmithers.com` | tested | scheme=https, server=GitHub.com, status=200 |

_3 assets recorded; showing the first 3. The JSON report contains up to 500._

## Assessment runs

| Run | Status | Started | Duration | Modules | Findings | Requests | Denials |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| `run_ec85bf29f60e` | completed | 2026-11-18 18:12 UTC | 2.9 s | 10 | 10 | 13 | 1 |

## Audit summary

| Metric | Count |
| --- | ---: |
| Network decisions recorded | 36 |
| Allowed | 35 |
| Denied by scope enforcement | 1 |
| Evidence records | 13 |

_A denied decision means the scope guard refused the action; it was not retried elsewhere._

## Limitations

- Testing was non-destructive: no exploitation, brute force, fuzzing at volume, credential attack or denial-of-service activity was performed. The report therefore does not demonstrate exploitability.
- Results reflect the state of the systems at the time of testing. Services, configuration and code change, so findings should be re-validated before remediation is considered complete.
- Only assets explicitly covered by the authorized scope were tested. Any host, path or port outside that scope was not assessed and may hold undiscovered issues.
- Absence of a finding is not proof that a vulnerability is absent. The checks are bounded by the recorded scope, request budget, timeouts and the enabled check set.

## Disclaimer

This report was produced by VANTAGE for the client named above under the authorization reference recorded in this document. It describes the state of the assessed systems at the time of testing and is limited to the scope, time window and check set recorded here. It is not a guarantee that the systems are free of vulnerabilities, and it does not constitute legal, compliance or certification advice. Distribution should be limited to parties authorized under the engagement.

_Report generated by VANTAGE 1.0.0 (schema 1) at 2026-11-18 18:12 UTC._
