---
title: D-Link DIR-645 Stack-Based Buffer Overflow Vulnerability (CVE-2026-5815)
slug: 2026-04-dlink-buffer-overflow
description: A remote stack-based buffer overflow vulnerability exists in the hedwigcgi_main function of the /cgi-bin/hedwig.cgi file on D-Link DIR-645 routers (versions 1.01, 1.02, and 1.03), potentially allowing unauthenticated attackers to execute arbitrary code.
date: "2026-04-09T00:16:20Z"
severities:
  - critical
tags:
  - cve-2026-5815
  - buffer-overflow
  - d-link
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5815
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5815
  - https://github.com/Pers1st0/CVE/blob/main/stack-based%20buffer%20overflow%20vulnerability%20exists%20in%20the%20hedwig.cgi%20of%20D-Link%20DIR-645.md
  - https://vuldb.com/vuln/356263
rules:
  - title: D-Link DIR-645 Buffer Overflow Attempt
    description: Detects potential buffer overflow attempts targeting the /cgi-bin/hedwig.cgi endpoint on D-Link DIR-645 routers.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: D-Link DIR-645 Unauthorized Access Attempt via hedwig.cgi
    description: Detects attempts to access the hedwig.cgi endpoint, potentially indicating exploitation of CVE-2026-5815 or other vulnerabilities.
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

CVE-2026-5815 describes a stack-based buffer overflow vulnerability affecting D-Link DIR-645 routers running firmware versions 1.01, 1.02, and 1.03. The vulnerability resides within the `hedwigcgi_main` function in the `/cgi-bin/hedwig.cgi` file.  Successful exploitation of this flaw could allow a remote, unauthenticated attacker to execute arbitrary code on the affected device. This vulnerability is particularly critical because a public exploit is available, increasing the likelihood of exploitation, although D-Link no longer supports the affected devices.

## Attack Chain

1.  The attacker sends a specially crafted HTTP request to the `/cgi-bin/hedwig.cgi` endpoint on the D-Link DIR-645 router.
2.  The web server processes the request and calls the `hedwigcgi_main` function.
3.  The `hedwigcgi_main` function copies user-supplied data from the HTTP request into a fixed-size buffer on the stack.
4.  The attacker provides a payload that exceeds the buffer's capacity, causing a buffer overflow.
5.  The overflow overwrites adjacent stack memory, including the return address.
6.  When the `hedwigcgi_main` function returns, it jumps to the attacker-controlled return address.
7.  The attacker-controlled return address points to shellcode injected by the attacker within the overflowing data.
8.  The shellcode executes with the privileges of the web server, potentially granting the attacker full control of the device.

## Impact

Successful exploitation of CVE-2026-5815 can lead to complete compromise of the D-Link DIR-645 router. An attacker could gain unauthorized access to the device's configuration, intercept network traffic, or use the compromised router as a launching point for further attacks on other devices on the network. Given that the affected devices are no longer supported, users will not receive patches, making exploitation more likely.

## Recommendation

*   Implement network segmentation to limit the impact of a compromised router.
*   Monitor web server logs for suspicious requests to `/cgi-bin/hedwig.cgi` using the provided Sigma rule to identify potential exploitation attempts.
*   Deploy the provided Sigma rule to your SIEM to detect exploitation attempts targeting CVE-2026-5815.
*   Consider replacing end-of-life D-Link DIR-645 routers with newer, supported models to eliminate the vulnerability.
