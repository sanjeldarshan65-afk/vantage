# Security policy

## Reporting a vulnerability in VANTAGE

Please report security problems in VANTAGE itself through [GitHub private vulnerability reporting](https://github.com/sanjeldarshan65-afk/vantage/security/advisories/new). Do not open a public issue. I aim to reply within 7 days.

Examples that count:

- a way to make the scope guard send traffic to a host or port outside the engagement scope
- the guard acting outside the authorization window
- the dashboard becoming reachable from another machine
- secrets surviving evidence redaction
- script injection through target-controlled data in the dashboard or reports

## Acceptable use

VANTAGE is for systems you own or are authorized in writing to assess. Every engagement records an authorization reference, an approver and a time window, and the guard refuses network actions outside them. Those records are there to keep you honest, not to replace a signed agreement.

Do not use VANTAGE against systems you do not have permission to test. Unauthorized testing is illegal in most countries, for example under the Computer Fraud and Abuse Act in the US and the Computer Misuse Act in the UK.

## What VANTAGE will not do

Every mode, including `full`, is non-destructive:

- no exploitation, brute forcing, credential attacks or fuzzing at volume
- no write methods against real paths
- no denial of service

Requests are rate-limited and capped by a per-engagement budget.
