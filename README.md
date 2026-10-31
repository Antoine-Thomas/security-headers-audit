# Security Headers Audit

Audit the HTTP security headers of a website URL and get a score out of 100,
plus the three highest-value corrections. One GET request, standard library
only, no API key, no account, no cloud.

This is a [Hermes Agent](https://github.com/NousResearch/hermes-agent) skill.
The scoring script also runs on its own: it needs Python 3.8+ and nothing else.

## Measured result

Run against a real WordPress site on shared hosting (o2switch):

| Date | Score | Note |
|---|---|---|
| before any header work | 0/100 | — |
| after configuring the headers | 87/100 | measured at the time |
| re-measured 2026-10-31 | **65/100** | CSP and Permissions-Policy are not currently served |

The current 65 is the honest, reproducible figure from this repository at
2026-10-31: HSTS, X-Frame-Options, X-Content-Type-Options and Referrer-Policy
pass; Content-Security-Policy (25 pts) and Permissions-Policy (10 pts) are
absent. So the earlier 87 was real but is not reproducible today — expect the
score to drop exactly by the weight of the headers that stop being sent.

The remaining gap to 100 is the Content-Security-Policy nonce/hash work on
WordPress, which is why the practical ceiling for this class of stack sits
around 90. The 87 measurement is a single observation on one site, not a
benchmark.

## What it does

1. Sends **one GET request** (no payload, no repeated probing).
2. Checks **six headers** and weights them:

   | Header | Points |
   |---|---|
   | Content-Security-Policy | 25 |
   | Strict-Transport-Security (HSTS) | 20 |
   | X-Frame-Options | 15 |
   | X-Content-Type-Options | 15 |
   | Referrer-Policy | 15 |
   | Permissions-Policy | 10 |

3. Computes a **score out of 100**.
4. Prints the **three priority corrections**.
5. Optionally writes a **markdown report** with a legal notice at the top and
   bottom.

## What it does not do

- No active scanning, no injection, no payload, no fuzzing.
- No automatic remediation — recommendations only, nothing is written to the
  target.
- No continuous monitoring.
- No authentication testing, no TLS cipher analysis, no cookie audit. This tool
  covers response headers and nothing else; a good score here is not a claim
  that a site is secure.

## Usage

```bash
python scripts/audit-headers.py https://example.com
python scripts/audit-headers.py https://example.com --output report.md
python scripts/audit-headers.py https://example.com --json
python scripts/audit-headers.py https://example.com --verbose
```

| Option | Effect |
|---|---|
| `url` (positional) | URL to audit — http(s) only |
| `--output FILE` / `-o` | Write the markdown report to a file |
| `--json` | Structured JSON output |
| `--verbose` / `-v` | Debug output |

Exit codes: `0` success, `1` error (invalid URL, private IP, unreachable host,
timeout, TLS error), `2` warning (HTTP status >= 400, partial analysis).

As a Hermes skill, copy this directory into the Hermes skills folder and ask
for a header audit by URL.

## Guardrails

- **10 s timeout** — the script never hangs.
- **Dedicated User-Agent**: `SecurityHeadersAudit/1.0 (Searching Murphy)`.
- **Private IPs refused**: `127.0.0.1`, `192.168.*`, `10.*`, `172.16-31.*`,
  `::1`, `localhost` — so it cannot be pointed at a LAN.
- **Non-http(s) schemes refused**: `ftp://`, `file://`, and friends.
- **One GET only.**

## Requirements

- Python 3.8+ (standard library only, zero dependencies)
- Outbound HTTPS (port 443)

## Documentation

- `references/headers-explained.md` — what each header does, why it matters, the
  recommended configuration.
- `references/score-rubric.md` — how the score is computed.
- `references/legal-disclaimer.md` — legal notice and responsible-use rules.
- `fixtures/sample-report.md` — an example generated report.

## Security and privacy

- No API key, no account, no cloud service.
- No secret is read, stored or transmitted; the script performs a single HTTP GET.
- No environment variables are read.
- Nothing is written except the file explicitly requested with `--output`.
- Reports contain nothing about the host running the audit.

## Scope of use

Only audit sites you own or are authorised to test. Sending one GET to a public
URL is broadly equivalent to visiting it in a browser, but the rule is yours to
respect: audit your own infrastructure, or get permission.

## Licence

MIT — see `LICENSE`. Free for personal and commercial use. The legal notice in
the generated reports must be kept.
