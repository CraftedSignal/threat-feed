---
title: 9Router Unauthenticated API Key Disclosure Vulnerability
slug: 2026-07-9router-api-keys
description: An unauthenticated information disclosure vulnerability, CVE-2026-62327, in 9Router through version 0.4.41 allows remote attackers to retrieve plaintext AI provider API keys via a missing authentication middleware on the Next.js API route accessible at /api/usage/stats, enabling unauthorized access to sensitive data, potential billing fraud, and quota exhaustion.
date: "2026-07-13T22:19:03Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - information-disclosure
  - vulnerability
  - web-application
  - cve
vendors:
  - 9Router
products:
  - 9Router <= 0.4.41
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: allows remote attackers to retrieve plaintext API keys for all connected AI provider accounts
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: allows remote attackers to retrieve plaintext API keys for all connected AI provider accounts
    confidence_band: high
cves:
  - id: CVE-2026-62327
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62327
rules:
  - title: Detect CVE-2026-62327 Exploitation - Unauthenticated API Key Disclosure
    description: Detects exploitation attempts for CVE-2026-62327, an unauthenticated information disclosure vulnerability in 9Router, by identifying successful unauthenticated HTTP GET requests to the /api/usage/stats endpoint that would leak AI provider API keys.
    platform: sigma
    severity: critical
    tactics:
      - collection
      - credential_access
    techniques:
      - T1552
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-62327 describes a critical unauthenticated information disclosure vulnerability affecting 9Router versions up to and including 0.4.41. This flaw allows remote attackers to retrieve plaintext API keys for all connected AI provider accounts by sending a single unauthenticated request to the `/api/usage/stats` endpoint. The vulnerability stems from missing authentication middleware on this specific Next.js API route. Successful exploitation grants attackers access to sensitive full API key strings, token counts, cost breakdowns, and request metadata. This direct access to AI provider credentials can lead to severe consequences, including unauthorized use of connected AI services, billing fraud, and exhaustion of legitimate user quotas.

## Attack Chain

1. An attacker identifies an internet-facing 9Router instance running a vulnerable version.
2. The attacker sends an unauthenticated HTTP GET request to the `/api/usage/stats` endpoint of the target 9Router application.
3. The 9Router application, due to a missing authentication middleware, processes the unauthenticated request.
4. The application retrieves internal usage statistics and plaintext AI provider API keys from its data stores.
5. The application constructs an HTTP response that includes the sensitive plaintext API keys, along with token counts, cost breakdowns, and request metadata.
6. The attacker receives the successful HTTP response containing the disclosed AI provider API keys.
7. The attacker then uses these stolen API keys to authenticate directly with AI provider services, bypassing legitimate user access controls.
8. This unauthorized access enables the attacker to make requests, incur charges, exhaust quotas, or potentially gain further access to associated accounts.

## Impact

A successful exploitation of CVE-2026-62327 results in the full compromise of all AI provider API keys configured within the vulnerable 9Router instance. This directly leads to unauthorized usage of connected AI services, allowing attackers to perform actions such as generating content, querying models, or consuming computational resources at the victim's expense. The financial impact can include significant billing fraud and the rapid exhaustion of pre-paid quotas. Additionally, the disclosure of API keys provides attackers with sensitive intelligence regarding the victim's AI consumption patterns and infrastructure, potentially enabling further targeted attacks or intellectual property theft.

## Recommendation

* Upgrade 9Router installations to a patched version immediately to remediate CVE-2026-62327.
* Deploy the Sigma rule "Detect CVE-2026-62327 Exploitation - Unauthenticated API Key Disclosure" to your SIEM system to detect attempts to access the vulnerable `/api/usage/stats` endpoint without authentication.
* Review web server logs for any unauthenticated GET requests to the `/api/usage/stats` URL path, specifically looking for successful (HTTP 200 OK) responses.
* Rotate all AI provider API keys that were connected to the 9Router instance and investigate for any unauthorized usage on the AI provider side.
