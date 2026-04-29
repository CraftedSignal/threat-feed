---
title: Tenda AC21 Router Buffer Overflow Vulnerability
slug: 2026-03-tenda-ac21-buffer-overflow
description: A buffer overflow vulnerability exists in Tenda AC21 firmware version 16.03.08.16, allowing remote attackers to execute arbitrary code by manipulating arguments to the formSetQosBand function.
date: "2026-03-23T01:16:43Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - tenda
  - ac21
  - buffer_overflow
  - cve-2026-4565
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4565
  - https://github.com/hellonestor/killallbug/issues/14
  - https://github.com/hellonestor/killallbug/releases/tag/poc
rules:
  - title: Detect Suspicious POST Requests to SetNetControlList
    description: Detects suspicious POST requests to the /goform/SetNetControlList endpoint, potentially indicating an exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda AC21 Buffer Overflow Attempt
    description: Detects attempts to exploit the buffer overflow vulnerability in Tenda AC21 routers by identifying overly long arguments in the query string.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical buffer overflow vulnerability, CVE-2026-4565, affects Tenda AC21 routers running firmware version 16.03.08.16. The flaw resides in the `formSetQosBand` function within the `/goform/SetNetControlList` file. Attackers can exploit this vulnerability by crafting malicious argument lists in HTTP requests, leading to arbitrary code execution on the device. The vulnerability can be exploited remotely and a proof-of-concept exploit is publicly available, increasing the risk of widespread exploitation. Successful exploitation allows attackers to gain complete control over the router, potentially compromising connected devices and network traffic.

## Attack Chain

1.  Attacker identifies a vulnerable Tenda AC21 router with firmware version 16.03.08.16.
2.  The attacker crafts a malicious HTTP POST request targeting the `/goform/SetNetControlList` endpoint.
3.  The POST request includes a specially crafted argument list designed to overflow the buffer in the `formSetQosBand` function.
4.  The router processes the HTTP request and passes the malicious arguments to the vulnerable function.
5.  The `formSetQosBand` function attempts to copy the oversized argument list into a fixed-size buffer, triggering a buffer overflow.
6.  The buffer overflow overwrites adjacent memory regions, potentially including critical program data or execution pointers.
7.  The attacker gains control of the program execution flow and injects malicious code.
8.  The injected code executes with elevated privileges, granting the attacker complete control over the router.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary code on the Tenda AC21 router. This can lead to a variety of malicious outcomes, including: complete device compromise, modification of router settings, interception of network traffic, deployment of malware to connected devices, and use of the router as a botnet node. Given the wide usage of Tenda routers in home and small business environments, a successful widespread exploit could impact thousands of users.

## Recommendation

*   Monitor web server logs for suspicious POST requests to `/goform/SetNetControlList` with unusually long or malformed arguments (see rule: "Detect Suspicious POST Requests to SetNetControlList").
*   Implement rate limiting on HTTP POST requests to prevent attackers from quickly exploiting the vulnerability.
*   Deploy the Sigma rule "Detect Tenda AC21 Buffer Overflow Attempt" to identify exploitation attempts based on specific patterns in HTTP requests.
*   Consider blocking traffic from known exploit sources, if available.
*   Upgrade to a patched firmware version as soon as it becomes available from the vendor.
