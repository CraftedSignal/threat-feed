---
title: WWBN AVideo SSRF Vulnerability (CVE-2026-41055)
slug: 2026-04-wwbn-avideo-ssrf
description: WWBN AVideo versions 29.0 and below are vulnerable to Server-Side Request Forgery (SSRF) due to an incomplete fix in the LiveLinks proxy, potentially allowing attackers to redirect traffic to internal endpoints.
date: "2026-04-22T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - avideo
  - cve-2026-41055
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-41055
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41055
  - https://github.com/WWBN/AVideo/commit/8d8fc0cadb425835b4861036d589abcea4d78ee8
iocs:
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious AVideo SSRF Attempt
    description: Detects potential SSRF attempts against AVideo by looking for requests with specific URI patterns indicative of the LiveLinks proxy feature.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo Outbound Connection to Private IP Ranges
    description: Detects AVideo making outbound connections to private IP address ranges, potentially indicating SSRF exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

WWBN AVideo, an open-source video platform, is vulnerable to Server-Side Request Forgery (SSRF) in versions 29.0 and below. The vulnerability, identified as CVE-2026-41055, stems from an incomplete fix in the LiveLinks proxy. While the fix introduced `isSSRFSafeURL()` validation, it fails to address Time-of-Check Time-of-Use (TOCTOU) vulnerabilities related to DNS rebinding. This flaw allows attackers to bypass the intended SSRF protection by manipulating DNS responses between the validation check and the actual HTTP request, potentially redirecting traffic to internal, sensitive endpoints. The vulnerability can be remediated by applying the updated fix found in commit 8d8fc0cadb425835b4861036d589abcea4d78ee8. Exploitation could lead to information disclosure or unauthorized access to internal services.

## Attack Chain

1. Attacker identifies an AVideo instance running a vulnerable version (<= 29.0).
2. Attacker crafts a malicious URL targeting the AVideo LiveLinks proxy feature.
3. The malicious URL is designed to leverage DNS rebinding techniques.
4. The AVideo server first validates the URL using `isSSRFSafeURL()`, which initially resolves to a safe, external IP address.
5. After validation, but before the HTTP request is made, the DNS record for the malicious URL is altered to point to an internal IP address.
6. The AVideo server, due to the TOCTOU vulnerability, now makes an HTTP request to the attacker-controlled internal IP address.
7. The attacker gains access to internal resources or services through the AVideo server.
8. Attacker exfiltrates sensitive data or pivots to other internal systems.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-41055) in WWBN AVideo could allow attackers to access sensitive internal resources that are not intended to be exposed to the public internet. An attacker could potentially read internal configuration files, access databases, or even execute commands on internal systems, depending on the exposed services. The specific impact will vary depending on the organization's internal network configuration and the services running behind the AVideo server.

## Recommendation

*   Upgrade WWBN AVideo to a version containing the complete SSRF fix, referencing commit 8d8fc0cadb425835b4861036d589abcea4d78ee8.
*   Implement network segmentation to limit the impact of potential SSRF vulnerabilities by restricting access from the AVideo server to only necessary internal resources.
*   Deploy the Sigma rule `Detect Suspicious AVideo SSRF Attempt` to detect potential exploitation attempts via web server logs.
*   Monitor web server logs for unusual outbound connections from the AVideo server to internal IP addresses based on the `network_connection` log source.
