---
title: Tenda CH22 Router Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-ch22-buffer-overflow
description: A stack-based buffer overflow vulnerability in Tenda CH22 version 1.0.0.1 allows a remote attacker to execute arbitrary code by manipulating the 'GO' argument in the formWrlExtraSet function via the /goform/WrlExtraSet endpoint.
date: "2026-04-06T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - CVE-2026-5605
  - buffer-overflow
  - tenda
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
cves:
  - id: CVE-2026-5605
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5605
  - https://github.com/Litengzheng/vuldb_new/blob/main/CH22/vul_54/README.md
  - https://vuldb.com/vuln/355397
rules:
  - title: Detect Tenda CH22 Buffer Overflow Attempt via Long GO Parameter
    description: Detects potential exploitation attempts of the Tenda CH22 buffer overflow vulnerability (CVE-2026-5605) by identifying abnormally long 'GO' parameters in POST requests to the /goform/WrlExtraSet endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Tenda CH22 formWrlExtraSet Endpoint
    description: Detects access to the /goform/WrlExtraSet endpoint on Tenda CH22 routers, which could indicate reconnaissance or exploitation attempts related to CVE-2026-5605.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, identified as CVE-2026-5605, affects Tenda CH22 router version 1.0.0.1. This flaw resides in the `formWrlExtraSet` function within the `/goform/WrlExtraSet` file. A remote, unauthenticated attacker can exploit a stack-based buffer overflow by sending a crafted HTTP request with a malicious value for the `GO` argument. Publicly available exploits exist, increasing the risk of widespread exploitation. Successful exploitation allows the attacker to potentially execute arbitrary code on the device, leading to a complete compromise of the router and the network it serves.

## Attack Chain

1.  The attacker identifies a vulnerable Tenda CH22 router running firmware version 1.0.0.1.
2.  The attacker crafts a malicious HTTP POST request targeting the `/goform/WrlExtraSet` endpoint.
3.  The crafted request includes the `GO` argument with a string exceeding the expected buffer size in the `formWrlExtraSet` function.
4.  The router's web server receives the request and passes the `GO` argument to the vulnerable function.
5.  The `formWrlExtraSet` function attempts to copy the oversized `GO` argument into a fixed-size buffer on the stack.
6.  This write operation overflows the buffer, overwriting adjacent memory regions, including the return address.
7.  When the `formWrlExtraSet` function returns, it jumps to the address overwritten by the attacker.
8.  The attacker's injected code executes with the privileges of the web server process, potentially allowing full control of the device.

## Impact

Successful exploitation of CVE-2026-5605 can lead to complete compromise of the Tenda CH22 router. This includes unauthorized access to network traffic, modification of router settings, and the potential for the router to be used as a pivot point for further attacks within the network. Given the ease of exploitation and the public availability of exploits, a large number of devices are potentially at risk, impacting both home and small business users.

## Recommendation

*   Monitor web server logs for POST requests to `/goform/WrlExtraSet` with unusually long `GO` parameter values to detect potential exploitation attempts. Use the Sigma rule provided below.
*   Implement rate limiting on requests to `/goform/WrlExtraSet` to mitigate brute-force exploitation attempts.
*   Since there is no patch available, consider replacing affected Tenda CH22 1.0.0.1 routers with devices from vendors with timely security updates.
