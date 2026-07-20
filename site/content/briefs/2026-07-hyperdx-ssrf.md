---
title: Server-Side Request Forgery in HyperDX via ClickHouse Proxy Test Endpoint
slug: 2026-07-hyperdx-ssrf
description: An authenticated attacker can exploit a Server-Side Request Forgery (SSRF) vulnerability, CVE-2026-63731, in HyperDX before version 2.31.0 by manipulating the `host` parameter of the ClickHouse proxy test endpoint, leading to disclosure of internal service response bodies and potential access to internal APIs, container services, and cloud provider metadata.
date: "2026-07-20T19:23:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - webserver
vendors:
  - HyperDX
products:
  - HyperDX (before 2.31.0)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Attackers can exploit the reflected error responses from the endpoint to disclose internal service response bodies, enabling access to internal APIs, container services, and cloud provider metadata endpoints.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1213
    technique_name: Data from Information Repositories
    evidence: Attackers can exploit the reflected error responses from the endpoint to disclose internal service response bodies, enabling access to internal APIs, container services, and cloud provider metadata endpoints.
    confidence_band: high
cves:
  - id: CVE-2026-63731
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63731
rules:
  - title: Detects CVE-2026-63731 Exploitation - HyperDX SSRF
    description: Detects exploitation attempts against CVE-2026-63731, an authenticated Server-Side Request Forgery (SSRF) vulnerability in HyperDX, by monitoring for requests to the ClickHouse proxy test endpoint with suspicious internal IP addresses or cloud metadata URLs in the 'host' parameter.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1213
      - T1592.002
    data_sources:
      - webserver
rules_count: 1
---

A critical Server-Side Request Forgery (SSRF) vulnerability, identified as CVE-2026-63731, affects HyperDX versions prior to 2.31.0. This flaw permits authenticated team members to direct the HyperDX server to arbitrary internal destinations. The vulnerability lies within the ClickHouse proxy test endpoint, which lacks proper URL validation and allowlist enforcement for the user-supplied `host` parameter. Exploiting this vulnerability allows attackers to read reflected error responses, which can contain sensitive internal service response bodies. This enables malicious actors to discover and potentially access internal APIs, container services, and cloud provider metadata endpoints, significantly increasing the risk of data exfiltration and further network compromise. Organizations using HyperDX should prioritize updating to version 2.31.0 or newer to mitigate this risk.

## Attack Chain

1. An authenticated team member (attacker) logs into the HyperDX platform, establishing an authorized session.
2. The attacker crafts a malicious HTTP request specifically targeting the vulnerable ClickHouse proxy test endpoint within the HyperDX application, typically located at a path like `/api/proxy/clickhouse/test`.
3. Within the request, the attacker injects an arbitrary internal IP address or domain (e.g., `169.254.169.254` for AWS EC2 metadata, `10.0.0.1` for an internal service) into the `host` parameter.
4. The HyperDX server, without proper validation, attempts to establish a connection to the attacker-specified internal host or service.
5. During this connection attempt, the server receives a response (or error) from the internal target, and this response body is reflected back to the attacker as part of the HyperDX application's HTTP response.
6. The attacker analyzes the reflected data, which may contain sensitive information such as cloud provider credentials, internal API keys, or details about running container services.
7. This disclosed information facilitates internal network reconnaissance, allowing the attacker to map the internal infrastructure and potentially gain access to further sensitive internal resources.

## Impact

Successful exploitation of CVE-2026-63731 can lead to significant information disclosure and internal network reconnaissance. Attackers can access sensitive data such as cloud provider metadata (e.g., AWS EC2 instance metadata containing temporary credentials), internal API endpoints, and details about container services running within the organization's infrastructure. While the vulnerability is authenticated, it allows an insider threat or an attacker who has compromised a legitimate user's credentials to escalate privileges and expand their foothold within the network. The CVSS v3.1 Base Score for this vulnerability is 7.7, indicating a high severity risk.

## Recommendation

* Patch CVE-2026-63731 immediately by updating HyperDX to version 2.31.0 or newer on all affected instances.
* Deploy the Sigma rule "Detects CVE-2026-63731 Exploitation - HyperDX SSRF" to your SIEM and tune for your environment to detect exploitation attempts.
* Enable comprehensive web server logging for all HyperDX instances to ensure `cs-uri-stem` and `cs-uri-query` fields are captured for the webserver category log source.
