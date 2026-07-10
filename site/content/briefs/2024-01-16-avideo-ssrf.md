---
title: AVideo SSRF Vulnerability via IPv4-Mapped IPv6 Bypass (CVE-2026-33480)
slug: 2024-01-16-avideo-ssrf
description: AVideo versions up to 26.0 are vulnerable to server-side request forgery (SSRF) due to a bypass in the `isSSRFSafeURL()` function, allowing unauthenticated attackers to access internal resources.
date: "2024-01-16T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssrf
  - avideo
  - cve-2026-33480
  - webserver
vendors:
  - AVideo
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33480
rules:
  - title: Detect AVideo SSRF Attempt via IPv6-Mapped Address
    description: Detects requests to the vulnerable proxy.php endpoint with IPv4-mapped IPv6 addresses.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo SSRF Attempt via Proxy Access
    description: Detects requests through the proxy.php endpoint accessing internal IP ranges.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

AVideo, an open-source video platform, is vulnerable to a Server-Side Request Forgery (SSRF) attack. Specifically, versions up to and including 26.0 contain a flaw in the `isSSRFSafeURL()` function. This function, intended to prevent SSRF attacks, can be bypassed using IPv4-mapped IPv6 addresses (e.g., `::ffff:x.x.x.x`). The vulnerability is located in the `plugin/LiveLinks/proxy.php` endpoint, which lacks proper authentication. An attacker can exploit this to make arbitrary HTTP requests to internal resources, cloud metadata endpoints, and localhost services. This issue was addressed in commit 75ce8a579a58c9d4c7aafe453fbced002cb8f373. The CVSS v3.1 score is 8.6, indicating a high level of severity.

## Attack Chain

1. An attacker identifies an AVideo instance running a vulnerable version (<= 26.0).
2. The attacker crafts a malicious URL using an IPv4-mapped IPv6 address, such as `::ffff:127.0.0.1`.
3. The attacker sends an HTTP request to the `plugin/LiveLinks/proxy.php` endpoint, providing the malicious URL as a parameter.
4. The `isSSRFSafeURL()` function fails to properly validate the IPv4-mapped IPv6 address.
5. The `proxy.php` script uses curl (or a similar function) to fetch the content from the attacker-controlled URL.
6. The curl request is sent to the target specified within the IPv6-mapped address (e.g., localhost).
7. The attacker gains access to sensitive information from internal services, cloud metadata, or localhost.
8. The attacker may further exploit accessed services or exfiltrate data depending on the internal resources exposed.

## Impact

Successful exploitation of this SSRF vulnerability allows unauthenticated attackers to read sensitive information from internal services, cloud metadata endpoints, and localhost services. This can lead to the disclosure of API keys, configuration files, internal network layouts, and potentially allow further exploitation of other internal systems. The lack of authentication on the affected endpoint greatly increases the potential for widespread abuse, particularly in cloud environments where metadata services are readily accessible.

## Recommendation

*   Apply the patch from commit 75ce8a579a58c9d4c7aafe453fbced002cb8f373 to remediate CVE-2026-33480.
*   Monitor web server logs for requests to the `plugin/LiveLinks/proxy.php` endpoint containing IPv4-mapped IPv6 addresses using the provided Sigma rule.
*   Implement network segmentation and firewall rules to restrict access from the AVideo server to internal resources to mitigate the impact of successful SSRF attacks.
