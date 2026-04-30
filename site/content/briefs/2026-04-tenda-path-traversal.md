---
title: Tenda i9 Path Traversal Vulnerability (CVE-2026-7036)
slug: 2026-04-tenda-path-traversal
description: CVE-2026-7036 is a path traversal vulnerability affecting the R7WebsSecurityHandlerfunction in the HTTP Handler component of Tenda i9 version 1.0.0.5(2204), allowing remote attackers to access sensitive files.
date: "2026-04-26T12:16:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-7036
  - path-traversal
  - tenda
  - network
vendors:
  - Tenda
products:
  - i9
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7036
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7036
  - https://github.com/Litengzheng/vuldb_new/blob/main/M3/vul_80/README.md
  - https://vuldb.com/vuln/359616
rules:
  - title: Detect Tenda i9 Path Traversal Attempt
    description: Detects potential path traversal attempts targeting web servers using common traversal sequences
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Web Request to Sensitive Files
    description: Detects web requests for sensitive files, potentially indicating path traversal
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-7036, exists in Tenda i9 version 1.0.0.5(2204). Specifically, the vulnerability resides in the R7WebsSecurityHandlerfunction of the HTTP Handler component. This flaw allows a remote, unauthenticated attacker to potentially access sensitive files and directories on the affected device. The vulnerability was reported on 2026-04-26, and a public exploit is reportedly available, increasing the risk of exploitation. This poses a significant threat to organizations using the affected Tenda i9 router, as it could lead to unauthorized access to sensitive information or system compromise.

## Attack Chain

1.  An attacker identifies a Tenda i9 router running firmware version 1.0.0.5(2204) accessible over the network.
2.  The attacker crafts a malicious HTTP request targeting the vulnerable R7WebsSecurityHandlerfunction.
3.  The crafted request includes a path traversal sequence (e.g., "../") within the URL or request parameters.
4.  The Tenda i9 router processes the malicious request without proper sanitization of the path.
5.  The R7WebsSecurityHandlerfunction incorrectly interprets the path traversal sequence, allowing access to files or directories outside the intended web root.
6.  The attacker gains unauthorized access to sensitive files, such as configuration files or system logs.
7.  The attacker may use the exposed information to further compromise the device or the network it is connected to.
8.  The attacker could potentially modify system files or execute commands, leading to full device compromise.

## Impact

Successful exploitation of CVE-2026-7036 can lead to unauthorized access to sensitive files on the Tenda i9 router. This includes configuration files containing credentials, system logs, or other confidential data. An attacker could leverage this access to gain further control of the device, potentially leading to a complete system compromise. While the number of affected devices is currently unknown, given the widespread use of Tenda routers, the potential impact could be significant.

## Recommendation

*   Deploy the provided Sigma rule to detect HTTP requests containing path traversal sequences targeting web servers to detect exploitation attempts (Sigma rule: "Detect Tenda i9 Path Traversal Attempt").
*   Since the source mentions a public exploit exists, prioritize patching or replacing vulnerable Tenda i9 routers to remediate CVE-2026-7036 immediately, if a patch becomes available.
*   Monitor web server logs for unusual file access patterns or requests containing suspicious path traversal sequences.
*   Implement web application firewall (WAF) rules to block requests containing path traversal sequences.
