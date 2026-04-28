---
title: Tenda F451 Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-buffer-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-6134) exists in Tenda F451 version 1.0.0.7_cn_svn7958, affecting the fromqossetting function of the /goform/qossetting file, allowing remote attackers to execute arbitrary code by manipulating the qos argument, with a public exploit available.
date: "2026-04-12T23:19:54Z"
severities:
  - critical
tags:
  - cve-2026-6134
  - buffer-overflow
  - tenda
  - router
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
  - id: CVE-2026-6134
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6134
  - https://github.com/Jimi-Lab/cve/issues/18
  - https://vuldb.com/vuln/356998
rules:
  - title: Tenda F451 QoS Buffer Overflow Attempt
    description: Detects attempts to exploit the CVE-2026-6134 buffer overflow vulnerability in Tenda F451 via a long 'qos' parameter in a POST request to /goform/qossetting.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Tenda F451 Goform Access
    description: Detects access to the goform page which is a common attack vector on Tenda F451 routers.
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

A critical stack-based buffer overflow vulnerability, CVE-2026-6134, has been identified in Tenda F451 router firmware version 1.0.0.7_cn_svn7958. This flaw resides within the `fromqossetting` function of the `/goform/qossetting` file. Successful exploitation allows remote attackers to execute arbitrary code on the affected device. The vulnerability is triggered by manipulating the `qos` argument. Given the public availability of a functional exploit, Tenda F451 devices running the vulnerable firmware version are at immediate risk of compromise. This impacts device confidentiality, integrity, and availability and may result in botnet inclusion or data exfiltration.

## Attack Chain

1.  Attacker identifies a vulnerable Tenda F451 router running firmware 1.0.0.7_cn_svn7958.
2.  The attacker sends a crafted HTTP POST request to `/goform/qossetting`.
3.  The POST request includes the `qos` argument with a payload exceeding the buffer's expected size.
4.  The `fromqossetting` function processes the `qos` argument without proper bounds checking.
5.  The oversized `qos` argument overwrites adjacent memory on the stack.
6.  The attacker manipulates the return address on the stack with the address of malicious code.
7.  The `fromqossetting` function returns, diverting execution to the attacker-controlled code.
8.  The attacker gains arbitrary code execution on the router, potentially leading to device takeover.

## Impact

Successful exploitation of CVE-2026-6134 allows attackers to execute arbitrary code on vulnerable Tenda F451 routers. This can lead to complete device compromise, enabling attackers to modify router settings, intercept network traffic, or use the device as part of a botnet. Given the high CVSS score (8.8), the availability of a public exploit, and the ease of remote exploitation, the potential impact is significant, ranging from service disruption to data breaches and further network intrusion.

## Recommendation

*   Deploy the Sigma rule `TendaF451QoSBufferOverflow` to detect malicious HTTP requests targeting the `/goform/qossetting` endpoint.
*   Block requests matching the pattern in the Sigma rule `TendaF451QoSBufferOverflow` at the network perimeter (firewall or IPS).
*   Monitor web server logs for HTTP POST requests to `/goform/qossetting` with unusually long `qos` parameter values.
*   Implement rate limiting for requests to `/goform/qossetting` to mitigate potential exploitation attempts.
