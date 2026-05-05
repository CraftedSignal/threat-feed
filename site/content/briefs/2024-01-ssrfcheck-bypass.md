---
title: ssrfcheck SSRF Bypass Vulnerability
slug: 2024-01-ssrfcheck-bypass
description: The `ssrfcheck` npm package is vulnerable to SSRF bypass due to an incomplete denylist of IP addresses. The package fails to classify the reserved IP address space 224.0.0.0/4 (Multicast) as invalid, allowing potential SSRF attacks. All versions up to and including 1.1.1 are affected. A patch has been released in version 1.2.0.
date: "2026-05-05T20:29:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - npm
vendors:
  - npmjs
products:
  - ssrfcheck (< 1.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-8267
    cvss: 8.2
    epss: 0.00119
references:
  - https://github.com/advisories/GHSA-p4hc-9pjh-55c8
  - https://nvd.nist.gov/vuln/detail/CVE-2025-8267
rules:
  - title: SSRFCheck Multicast Bypass
    description: Detects attempts to bypass ssrfcheck by using a multicast IP address.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: SSRFCheck Multicast Bypass - Host Header
    description: Detects attempts to bypass ssrfcheck by using a multicast IP address in the Host header.
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

The `ssrfcheck` npm package, designed to protect against Server-Side Request Forgery (SSRF) attacks, contains a vulnerability due to an incomplete IP address denylist. Specifically, the package fails to classify the reserved IP address space `224.0.0.0/4` (Multicast) as invalid. This omission allows attackers to bypass the intended SSRF protection mechanisms. The vulnerability affects all versions of `ssrfcheck` up to and including version `1.1.1`. This issue came to light in early May 2026. Although multicast addresses are typically used for local network communication, their acceptance by `ssrfcheck` deviates from established security practices and could be exploited in certain SSRF scenarios. The maintainers have released version 1.2.0 to address this vulnerability, incorporating the missing reserved IP range into the denylist.

## Attack Chain

1.  An attacker identifies a web application that utilizes the vulnerable `ssrfcheck` package for URL validation.
2.  The attacker crafts a malicious URL containing an address within the `224.0.0.0/4` IP range (e.g., `239.255.255.250`).
3.  The web application uses `ssrfcheck`'s `isSSRFSafeURL` function to validate the URL.
4.  Due to the missing IP range in `ssrfcheck`'s denylist, the function incorrectly returns `true`, indicating the URL is safe.
5.  The web application proceeds to make a request to the attacker-controlled multicast address.
6.  The request is routed within the internal network, potentially targeting internal services or resources that are not exposed to the public internet.
7.  The attacker gains unauthorized access to sensitive data or functionality within the internal network.
8.  The attacker exfiltrates the obtained information or uses the compromised service as a pivot point for further attacks within the network.

## Impact

Successful exploitation of this SSRF vulnerability could allow attackers to bypass intended security controls and access internal network resources. While the use of multicast addresses may limit the scope of potential attacks, it still presents a risk of unauthorized access to sensitive information and systems. The vulnerability affects all users of the `ssrfcheck` package up to version 1.1.1. Web applications relying on `ssrfcheck` for SSRF protection are vulnerable until the package is updated to version 1.2.0 or later.

## Recommendation

*   Upgrade the `ssrfcheck` package to version 1.2.0 or later to remediate the vulnerability.
*   Deploy the Sigma rule `SSRFCheck_Multicast_Bypass` to detect attempts to exploit this vulnerability in your environment.
*   Review and audit any custom SSRF protection mechanisms that may be in place to ensure they adequately address reserved IP address spaces.
*   Monitor network traffic for connections to multicast addresses originating from web applications that rely on URL validation.
*   Update your vulnerability management system to include CVE-2025-8267 for tracking and remediation purposes.
*   Implement network segmentation to limit the impact of potential SSRF attacks, even if the vulnerable package is exploited.
