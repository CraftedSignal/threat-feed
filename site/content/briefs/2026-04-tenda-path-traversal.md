---
title: Tenda i3 Path Traversal Vulnerability (CVE-2026-5841)
slug: 2026-04-tenda-path-traversal
description: A path traversal vulnerability (CVE-2026-5841) exists in the R7WebsSecurityHandler function of the HTTP Handler component in Tenda i3 version 1.0.0.6(2204), allowing a remote attacker to bypass authentication and potentially access sensitive files due to publicly available exploits.
date: "2026-04-09T05:16:06Z"
severities:
  - high
tags:
  - path-traversal
  - tenda
  - cve-2026-5841
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5841
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5841
  - https://github.com/MrXiaoFan/TendaVul/tree/main/tenda-i3-V1.0.0.6(2204)-R7WebsSecurityHandler-Authentication%20Bypass%20Issues
  - https://vuldb.com/submit/789935
  - https://vuldb.com/vuln/356297
  - https://vuldb.com/vuln/356297/cti
  - https://www.tenda.com.cn/
iocs:
  - type: url
    value: https://github.com/MrXiaoFan/TendaVul/tree/main/tenda-i3-V1.0.0.6(2204)-R7WebsSecurityHandler-Authentication%20Bypass%20Issues
  - type: url
    value: https://vuldb.com/submit/789935
  - type: url
    value: https://vuldb.com/vuln/356297
  - type: url
    value: https://vuldb.com/vuln/356297/cti
  - type: url
    value: https://www.tenda.com.cn/
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
  url: 5
rules:
  - title: Detect Tenda i3 Path Traversal Attempts via Web Logs
    description: Detects path traversal attempts in HTTP requests targeting Tenda i3 devices, potentially exploiting CVE-2026-5841.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1133
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda i3 Path Traversal Attempts via Web Logs (Encoded)
    description: Detects path traversal attempts with URL encoded characters in HTTP requests targeting Tenda i3 devices, potentially exploiting CVE-2026-5841.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1133
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical path traversal vulnerability has been identified in Tenda i3 router firmware version 1.0.0.6(2204). The vulnerability, tracked as CVE-2026-5841, resides within the R7WebsSecurityHandler function of the HTTP Handler component. This flaw allows unauthenticated remote attackers to manipulate requests and potentially gain unauthorized access to sensitive files and directories on the device. The vulnerability is considered high risk due to the availability of public exploits, increasing the likelihood of widespread exploitation targeting vulnerable Tenda i3 devices. Successful exploitation could lead to information disclosure and further compromise of the affected network.

## Attack Chain

1.  The attacker identifies a Tenda i3 router running firmware version 1.0.0.6(2204).
2.  The attacker crafts a malicious HTTP request targeting the R7WebsSecurityHandler function.
3.  The crafted request includes path traversal sequences (e.g., "../") to escape the intended directory.
4.  The HTTP Handler processes the request without proper sanitization of the path.
5.  The attacker bypasses authentication checks due to the path traversal vulnerability.
6.  The attacker gains unauthorized access to sensitive files or directories on the device.
7.  The attacker exfiltrates sensitive information, such as configuration files or user credentials.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to the affected Tenda i3 router. This can lead to the disclosure of sensitive information, such as router configuration details and user credentials. With access to configuration files, attackers could potentially reconfigure the router, intercept network traffic, or use the compromised device as a foothold for further attacks within the network. Given the public availability of exploits, there is a high risk of widespread exploitation targeting vulnerable Tenda i3 devices.

## Recommendation

*   Apply available patches or firmware updates from Tenda to address CVE-2026-5841.
*   Monitor web server logs for suspicious HTTP requests containing path traversal sequences (e.g., "../") targeting the Tenda i3 device; create a Sigma rule to detect these patterns.
*   Restrict network access to the Tenda i3 device from untrusted sources using firewall rules.
*   Monitor network traffic for unusual file access patterns originating from the Tenda i3 device, indicative of successful path traversal and data exfiltration.
*   Use network IDS/IPS systems to detect and block exploitation attempts targeting CVE-2026-5841.
