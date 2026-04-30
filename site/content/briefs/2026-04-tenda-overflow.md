---
title: Tenda F451 Stack-Based Buffer Overflow Vulnerability (CVE-2026-6121)
slug: 2026-04-tenda-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-6121) exists in the WrlclientSet function of the /goform/WrlclientSet file in the httpd component of Tenda F451 version 1.0.0.7, allowing remote attackers to execute arbitrary code by manipulating the GO argument.
date: "2026-04-12T08:16:36Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-6121
  - buffer-overflow
  - tenda
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6121
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6121
  - https://github.com/Jimi-Lab/cve/issues/12
  - https://vuldb.com/vuln/356984
rules:
  - title: Detect Suspiciously Long GO Parameter in Tenda WrlclientSet Request
    description: Detects HTTP POST requests to the /goform/WrlclientSet endpoint with an unusually long GO parameter, indicative of a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - exploitation
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP POST to /goform/WrlclientSet
    description: Detects HTTP POST requests to the /goform/WrlclientSet endpoint.
    platform: sigma
    severity: low
    tactics:
      - exploitation
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-6121 is a stack-based buffer overflow vulnerability affecting Tenda F451 router version 1.0.0.7. The vulnerability resides within the `WrlclientSet` function located in the `/goform/WrlclientSet` file of the `httpd` component. An attacker can exploit this vulnerability by sending a specially crafted HTTP request to the affected router, specifically manipulating the `GO` argument. Due to insufficient bounds checking on the `GO` argument's size when passed to the `WrlclientSet` function, an attacker can write beyond the allocated buffer on the stack, potentially leading to arbitrary code execution. Publicly available exploits exist, increasing the risk of widespread exploitation. Routers that are accessible from the internet are at highest risk.

## Attack Chain

1.  Attacker identifies a Tenda F451 router version 1.0.0.7 exposed to the internet.
2.  The attacker crafts a malicious HTTP POST request targeting the `/goform/WrlclientSet` endpoint.
3.  Within the HTTP POST request, the attacker includes the `GO` argument, filling it with a payload exceeding the buffer size allocated for it within the `WrlclientSet` function.
4.  The `httpd` component of the Tenda F451 router receives the HTTP request and passes the `GO` argument to the vulnerable `WrlclientSet` function.
5.  Due to the buffer overflow, the attacker's payload overwrites adjacent memory locations on the stack.
6.  The attacker's payload overwrites the return address on the stack, redirecting execution flow to attacker-controlled code.
7.  The attacker-controlled code executes with the privileges of the `httpd` process, allowing the attacker to perform actions such as modifying router configuration, executing system commands, or establishing a reverse shell.
8.  The attacker gains persistent access to the router and potentially the internal network.

## Impact

Successful exploitation of CVE-2026-6121 can lead to complete compromise of the affected Tenda F451 router. An attacker can gain unauthorized access to the device's configuration, potentially modifying DNS settings, firewall rules, or other critical parameters. This can lead to redirection of user traffic, denial-of-service attacks, or the establishment of a foothold within the targeted network for further malicious activities. Given the ease of exploitation due to the publicly available exploit code, a large number of Tenda F451 routers could be compromised.

## Recommendation

*   Monitor web server logs for POST requests to `/goform/WrlclientSet` with abnormally long `GO` parameter values to detect potential exploitation attempts (see Sigma rule below and enable webserver logging).
*   Implement rate limiting for requests to the `/goform/WrlclientSet` endpoint to mitigate potential brute-force exploitation attempts (configure your firewall or WAF).
*   Upgrade to a patched firmware version when available or replace the affected devices, if the vendor does not provide a fix.
