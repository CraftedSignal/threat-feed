---
title: OpenClaw SSRF Vulnerability (CVE-2026-62227) Allows Network Policy Bypass
slug: 2026-07-openclaw-ssrf
description: A server-side request forgery (SSRF) vulnerability, CVE-2026-62227, in OpenClaw versions before 2026.5.26 allows attackers with lower-trust access to bypass network policy checks through browser snapshot routes, leading to unauthorized access to internal network destinations.
date: "2026-07-17T02:33:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - web-application
vendors:
  - OpenClaw
products:
  - OpenClaw (>= 2026.4.14, < 2026.5.26)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Attackers with lower-trust access can bypass OpenClaw policy checks to reach network destinations that should have been blocked.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Scanning
    evidence: reach network destinations that should have been blocked
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: effectively using the server as a proxy to access otherwise unreachable resources
    confidence_band: high
cves:
  - id: CVE-2026-62227
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62227
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-2x93-h3hg-2xfp
  - https://www.vulncheck.com/advisories/openclaw-ssrf-via-browser-snapshot
rules:
  - title: Detects CVE-2026-62227 Exploitation - OpenClaw SSRF via Internal Hostnames or IPs
    description: Detects exploitation attempts for CVE-2026-62227 by looking for internal IP addresses, localhost, or file/gopher schemes within HTTP request query parameters or URIs directed at OpenClaw browser snapshot routes, indicative of Server-Side Request Forgery.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - discovery
    techniques:
      - T1046
      - T1090
      - T1562
    data_sources:
      - webserver
rules_count: 1
---

A significant server-side request forgery (SSRF) vulnerability, identified as CVE-2026-62227, has been discovered in OpenClaw versions 2026.4.14 through 2026.5.25. This flaw resides within the browser snapshot routes where the application fails to properly validate post-navigation destinations. Attackers who have already obtained lower-trust access to an OpenClaw instance can exploit this vulnerability to bypass internal network policy checks. By crafting specific requests, they can force the OpenClaw server to initiate connections to arbitrary internal or restricted network destinations that would normally be blocked, effectively using the server as a proxy to access otherwise unreachable resources. The exploitation of this vulnerability could lead to unauthorized information disclosure, reconnaissance of internal networks, or even further attacks on internal services.

## Attack Chain

1. An attacker obtains "lower-trust access" to a vulnerable OpenClaw instance, potentially via a compromised user account or another initial access vector.
2. The attacker identifies a vulnerable browser snapshot route within the OpenClaw application.
3. The attacker crafts a malicious HTTP request targeting this snapshot route, embedding an internal or restricted network URL (e.g., `http://127.0.0.1/admin` or `http://10.0.0.1/internal-api`) as the post-navigation destination.
4. The OpenClaw server processes this crafted request. Due to the SSRF vulnerability (CVE-2026-62227), it fails to properly validate the embedded internal destination.
5. OpenClaw's server-side component then initiates an HTTP request from its own context to the attacker-specified internal destination.
6. The OpenClaw server acts as an unwitting proxy, retrieving the content or executing the request against the internal network resource.
7. The attacker receives the response from the internal resource via the OpenClaw server, thereby bypassing network segmentation and security policies.
8. The attacker can use the gained access or information for further reconnaissance, lateral movement, or data exfiltration from the internal network.

## Impact

A successful exploitation of CVE-2026-62227 allows attackers to gain unauthorized access to internal network resources and services that should typically be inaccessible from the OpenClaw instance. This can lead to sensitive information disclosure, exposure of internal APIs, or mapping of the internal network topology. Such access could serve as a stepping stone for further sophisticated attacks, including lateral movement, exploitation of other internal vulnerabilities, or exfiltration of proprietary data, ultimately compromising the confidentiality, integrity, and availability of internal systems.

## Recommendation

* Patch CVE-2026-62227 immediately by upgrading OpenClaw to version 2026.5.26 or later to address the SSRF vulnerability.
* Deploy the Sigma rule provided in this brief to your SIEM to detect attempts to exploit SSRF by identifying suspicious patterns in webserver logs.
* Ensure comprehensive webserver logging is enabled for all OpenClaw instances, capturing full HTTP request details, including method, URI stem, and query parameters.
* Implement robust network segmentation and egress filtering to limit the OpenClaw server's ability to initiate connections to internal network segments or sensitive services, even if an SSRF vulnerability is exploited.
