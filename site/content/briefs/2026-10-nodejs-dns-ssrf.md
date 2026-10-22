---
brief_id: brief-2026-10-21-nodejs-dns-ssrf
event_id: brief-2026-10-21-nodejs-dns-ssrf
revision: 3
activity_at: "2026-10-22T22:18:10Z"
revision_history:
  - revision: 2
    at: "2026-10-22T09:36:28Z"
    checksum: sha256:9b461b897af9efa28e3e7bf989ed35eb4a46afa0f624b71620734635994bf095
    summary: added coverage for Node.js (22.x, 24.x, 26.x)
    changed_fields:
      - affected_products
      - lastmod
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://thehackernews.com/2026/10/nodejs-brotli-decoder-bug-could-allow.html
  - revision: 3
    at: "2026-10-22T22:18:10Z"
    checksum: sha256:95270112bd31082a86390a33aca58482196fb4c26df0a657c8522dc0a94491a1
    summary: added coverage for Node.js (22.x < 22.23.4, 24.x < 24.22.1, 26.x < 26.12.1) +1 products
    changed_fields:
      - affected_products
      - affected_vendors
      - lastmod
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=FA050262-2C57-5CB9-911F-4281149901A9&utm_source=rss&utm_medium=rss
title: 'Node.js: DNS Resolver NUL Byte Truncation (CVE-2026-105482)'
slug: 2026-10-nodejs-dns-ssrf
description: Node.js is vulnerable to NUL byte truncation in dns.resolve* functions, allowing attackers to bypass allowlist filters and perform SSRF by injecting a NUL character into hostname strings.
date: "2026-10-21T17:05:59Z"
lastmod: "2026-10-22T22:17:29Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Ready for deployment.
cpes:
  - cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - nodejs
  - dns
  - vulnerability
  - web-security
  - supply-chain
  - cve-2026-111497
  - denial-of-service
  - brotli
vendors:
  - Node.js
  - Google
products:
  - Node.js (< 22.23.4, < 24.22.1, < 26.12.1)
  - Node.js (22.x, 24.x, 26.x)
  - Node.js (22.x < 22.23.4, 24.x < 24.22.1, 26.x < 26.12.1)
  - Brotli (1.0.10, 1.1.1, 1.2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: NUL byte truncation in Node.js dns.resolve* allows host allowlist bypass to SSRF.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The most serious is a bug in the Brotli decompression code that Node.js bundles, which the project says can allow remote code execution.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: 'Practical impact: DoS (infinite CPU loop) via header corruption, not RCE.'
    confidence_band: high
cves:
  - id: CVE-2026-105482
    kev_status: unknown
  - id: CVE-2026-111497
    kev_status: unknown
references:
  - https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
  - https://sploitus.com/exploit?id=4E75DBD2-8E80-56B2-BDA5-0C8BE7F08DA8
  - https://sploitus.com/exploit?id=4E75DBD2-8E80-56B2-BDA5-0C8BE7F08DA8&utm_source=rss&utm_medium=rss
  - https://thehackernews.com/2026/10/nodejs-brotli-decoder-bug-could-allow.html
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1367/
  - https://github.com/google/brotli/commit/0ed4268a
  - https://sploitus.com/exploit?id=FA050262-2C57-5CB9-911F-4281149901A9&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-105482 - Potential SSRF via NUL Byte in Hostname
    description: Detects attempts to pass hostnames containing a NUL byte to Node.js DNS resolver functions, which is indicative of an allowlist bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Patch Node.js to 22.23.4, 24.22.1, or 26.12.1.
      owner: IT Operations
      due: 24h
      evidence: Node.js security release notes indicate these versions contain the fix.
  hunt_leads:
    - lead: Search application and web server logs for requests containing %00 or 0x00 bytes in URL parameters.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source indicates NUL byte injection is the core mechanism of bypass.
  mitigation_plan:
    - priority: immediate
      action: Upgrade affected Node.js products.
      owner: IT Operations
      addresses: CVE-2026-105482
      evidence: Node.js October 2026 security release.
  gaps:
    - Visibility into non-web SSRF vectors such as message queues or local configuration files.
updates:
  - at: "2026-10-22T09:35:55Z"
    level: L2
    summary: added coverage for Node.js (22.x, 24.x, 26.x)
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/10/nodejs-brotli-decoder-bug-could-allow.html
  - at: "2026-10-22T22:17:29Z"
    level: L2
    summary: added coverage for Node.js (22.x < 22.23.4, 24.x < 24.22.1, 26.x < 26.12.1) +1 products
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=FA050262-2C57-5CB9-911F-4281149901A9&utm_source=rss&utm_medium=rss
---

Node.js versions before 22.23.4, 24.22.1, and 26.12.1 are vulnerable to a NUL byte truncation issue within the `dns.resolve*` functions. The vulnerability exists because these functions pass hostname strings to the c-ares library, which processes them as C-style strings. When a NUL byte (`\0`) is included in a hostname (e.g., `attacker.com\0.trusted.corp`), application-level allowlist checks may evaluate the full string as legitimate, but the underlying DNS resolver truncates the string at the NUL byte, resulting in a query to an attacker-controlled domain. This flaw enables Server-Side Request Forgery (SSRF) against internal services.

## Impact
Successful exploitation allows an attacker to bypass domain-based allowlists implemented via `endsWith`, `includes`, or `match` functions. This facilitates SSRF attacks against internal infrastructure, including `169.254.169.254` (metadata services), local services, or restricted internal network assets.

## Recommendation
- Upgrade Node.js installations to the patched versions: 22.23.4, 24.22.1, or 26.12.1.
- Implement application-level input validation to reject hostnames containing a NUL byte (`\0`) before passing them to DNS resolution functions.
- Audit custom security wrappers that rely on hostname string comparisons to filter outgoing traffic or allowlist internal resources.
