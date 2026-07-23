---
title: CVE-2026-63313 - Server-Side Request Forgery in 9Router
slug: 2026-07-9router-ssrf
description: 9Router versions prior to 0.4.72 contain a server-side request forgery (SSRF) vulnerability in the /v1/web/fetch endpoint, allowing an authenticated or locally-connected user to bypass URL validation to fetch arbitrary internal URLs, potentially exposing cloud metadata credentials, accessing internal services, and bypassing authentication on localhost endpoints.
date: "2026-07-23T22:24:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - web-application
  - router
vendors:
  - 9Router
products:
  - 9Router < 0.4.72
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 9Router before 0.4.72 contains a server-side request forgery (SSRF) vulnerability in the /v1/web/fetch endpoint.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: exposing cloud metadata credentials
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Scanning
    evidence: reach internal services
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1213
    technique_name: Exploitation for Defense Evasion
    evidence: bypass authentication on localhost endpoints
    confidence_band: high
cves:
  - id: CVE-2026-63313
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63313
rules:
  - title: Detects CVE-2026-63313 Exploitation - 9Router SSRF via Internal IPs
    description: Detects CVE-2026-63313 exploitation attempts against 9Router via HTTP POST requests to /v1/web/fetch containing internal IP addresses or cloud metadata endpoints in the 'url' query parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
---

A critical server-side request forgery (SSRF) vulnerability, identified as CVE-2026-63313, affects 9Router software versions prior to 0.4.72. The vulnerability resides within the `/v1/web/fetch` endpoint, which is designed to accept a user-controlled URL parameter for content scraping via external providers like Firecrawl, Jina Reader, Tavily, or Exa. The core issue stems from insufficient URL validation, as the system only checks for syntactic validity using `new URL()` without implementing a blocklist for private IP ranges, cloud metadata endpoints (e.g., 169.254.169.254), link-local addresses, or internal hostnames. This flaw enables an authenticated or locally-connected attacker to force the 9Router server to make requests to arbitrary internal URLs, facilitating read-access SSRF. This can lead to the exposure of sensitive cloud metadata credentials, unauthorized access to internal network services, and the bypassing of authentication mechanisms on localhost endpoints. The vulnerability has a CVSS v3.1 Base Score of 7.7.

## Attack Chain

1. An authenticated or locally-connected attacker crafts a malicious URL payload targeting an internal resource (e.g., `http://169.254.169.254/latest/meta-data/iam/security-credentials/`).
2. The attacker sends an HTTP POST request to the 9Router `/v1/web/fetch` endpoint, including the malicious URL within the `url` parameter.
3. The 9Router server receives the request and performs a basic syntactic validation of the provided URL using `new URL()`.
4. Due to the lack of a blocklist for internal IP ranges, the 9Router server initiates a request to the attacker-specified internal URL via one of its configured external scraping providers (e.g., Firecrawl).
5. The external scraping provider (or the 9Router server itself in some configurations) fetches the content from the internal target (e.g., cloud metadata service or an internal API endpoint).
6. The sensitive response content (e.g., temporary AWS credentials, internal configuration data, session tokens) is returned to the 9Router server.
7. The 9Router server then returns the fetched content to the attacker in its response, completing the SSRF exploitation and exfiltrating internal data.

## Impact

Successful exploitation of CVE-2026-63313 grants attackers read-access to internal network resources, leading to severe consequences. The primary impacts include the potential exposure of cloud metadata credentials, which can be leveraged for further unauthorized access within cloud environments. Attackers can also gain unauthorized access to internal services and bypass authentication mechanisms on localhost endpoints, potentially leading to privilege escalation or lateral movement within the compromised network. This read-access SSRF capability allows for extensive information gathering and reconnaissance, laying the groundwork for more sophisticated attacks against the affected organization.

## Recommendation

* Patch CVE-2026-63313 immediately by updating 9Router to version 0.4.72 or later on all deployed instances.
* Deploy the Sigma rule "Detects CVE-2026-63313 Exploitation - 9Router SSRF via Internal IPs" to your SIEM and investigate any alerts on POST requests to `/v1/web/fetch` with internal IP addresses or cloud metadata URLs in the query parameters.
* Ensure webserver logs (category: webserver) for all internet-facing 9Router instances are collected and ingested into your SIEM for analysis by the provided Sigma rule.
