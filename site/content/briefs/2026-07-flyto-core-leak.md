---
title: Credential Exfiltration via Unrestricted Base URL in Flyto-core
slug: 2026-07-flyto-core-leak
description: Flyto-core versions prior to 2.26.7 allow unauthenticated callers to exfiltrate API provider keys by supplying a malicious 'base_url' parameter, which forces the library to append operator-configured secrets to requests sent to attacker-controlled infrastructure.
date: "2026-07-30T15:29:30Z"
lastmod: "2026-07-30T15:29:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-theft
  - vulnerability
  - cloud-security
  - cve-2026-67425
  - cve-2026-67427
  - exfiltration
  - flyto
  - variable-interpolation
vendors:
  - Flyto
products:
  - flyto-core (< 2.26.7)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: 'llm.chat reads the operator''s provider key from the environment (OPENAI_API_KEY, ANTHROPIC_API_KEY, ...) and sends it in the Authorization: Bearer header to base_url'
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: 'await client.post(url, headers=headers, json=payload) # sent to base_url'
    confidence_band: high
cves:
  - id: CVE-2026-67425
    cvss: 8.6
    epss: 0.00319
references:
  - https://github.com/advisories/GHSA-hr7p-wg7r-hg9m
updates:
  - at: "2026-07-30T15:29:38Z"
    level: L2
    summary: 'merged source coverage: Flyto Core Variable Resolver Environment Variable Exfiltration'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-hr7p-wg7r-hg9m
---

Flyto-core is susceptible to a credential exfiltration vulnerability (CVE-2026-67425) affecting multiple modules including `llm.chat`, `ai.model`, `llm.agent`, and `vector.connector`. The vulnerability exists because the library automatically fetches sensitive environment variables, such as `OPENAI_API_KEY` or `QDRANT_API_KEY`, and appends them as `Authorization: Bearer` headers to outgoing HTTP requests. While the library implements an SSRF guard, this mechanism only validates that the target host is not private; it does not prevent the application from sending requests to public, attacker-controlled servers. An attacker capable of influencing the `base_url` parameter via the MCP agent surface or hosted API can redirect these requests to an arbitrary public endpoint, successfully capturing the operator's environment-stored credentials. This vulnerability affects all `flyto-core` versions prior to 2.26.7 and can result in significant financial and data impact through unauthorized account usage.

## Attack Chain

1. Attacker identifies an exposed application interface that interacts with `flyto-core` and allows user-supplied parameters.
2. Attacker crafts a payload specifically targeting the `base_url` parameter within the library's `llm.chat` or `ai.model` functions.
3. Attacker points `base_url` to a custom-controlled public web server capable of capturing inbound HTTP headers.
4. The victim application receives the malicious request and passes the `base_url` parameter to the vulnerable library functions.
5. `flyto-core` performs an SSRF check, which validates that the attacker's public URL is not a private IP, allowing the request to proceed.
6. The library retrieves the operator's secret key from environment variables (e.g., `OPENAI_API_KEY`).
7. The library transmits a POST request to the attacker's server, attaching the secret key in the `Authorization: Bearer` header.
8. Attacker logs the incoming request, extracts the Bearer token, and uses it to perform unauthorized API calls on behalf of the victim.

## Impact

Successful exploitation results in the exfiltration of high-privilege cloud LLM and vector database credentials. Attackers can leverage these keys to incur fraudulent billing costs, exfiltrate sensitive data accessible to the LLM or vector store, or manipulate internal AI workflows. The ease of triggering this via the library's exposed API surfaces makes this a critical risk for any organization utilizing vulnerable versions of `flyto-core`.

## Recommendation

1. Upgrade `flyto-core` to version 2.26.7 or higher immediately to apply the vendor-supplied patches (CVE-2026-67425).
2. Audit application code to identify all calls to `llm.chat`, `ai.model`, `llm.agent`, and `vector.connector` where user-controlled input influences the `base_url` parameter.
3. Implement strict allowlisting for allowed API endpoints rather than relying on SSRF guards for credential-handling components.
4. Rotate any API keys that were potentially exposed in environment variables if the application was reachable by untrusted actors.
