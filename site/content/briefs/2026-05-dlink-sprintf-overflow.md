---
title: D-Link DI-8100 Stack-Based Buffer Overflow Vulnerability
slug: 2026-05-dlink-sprintf-overflow
description: A stack-based buffer overflow vulnerability exists in D-Link DI-8100 with firmware version 16.07.26A1, affecting the sprintf function in the yyxz.asp file; manipulation of the ID argument can lead to remote exploitation.
date: "2026-05-05T18:16:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer-overflow
  - d-link
  - router
  - cve-2026-7851
vendors:
  - D-Link
products:
  - DI-8100 firmware 16.07.26A1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7851
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7851
  - https://github.com/draw-ctf/report/blob/main/DI-8100/yyxz_dlink_asp_overflow.md
  - https://vuldb.com/vuln/361128
rules:
  - title: Detect D-Link DI-8100 yyxz.asp Stack Overflow Attempt
    description: Detects potential attempts to exploit the stack overflow vulnerability in D-Link DI-8100's yyxz.asp page by monitoring for abnormally long ID parameters in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - exploitation
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect D-Link DI-8100 HTTP 400 Errors to yyxz.asp
    description: Detects HTTP 400 errors when accessing /yyxz.asp, which may indicate a buffer overflow due to overly long input.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stack-based buffer overflow vulnerability has been identified in D-Link DI-8100 routers running firmware version 16.07.26A1. The vulnerability resides within the `sprintf` function of the `yyxz.asp` file. Successful exploitation allows remote attackers to execute arbitrary code. Publicly available exploit code exists, increasing the risk of widespread exploitation targeting these devices. Given the potential for complete system compromise, this poses a significant risk to affected D-Link router users.

## Attack Chain

1.  Attacker sends a malicious HTTP request to the vulnerable D-Link DI-8100 device.
2.  The request targets the `yyxz.asp` file.
3.  The `ID` argument in the request is manipulated to contain an overly long string.
4.  The `sprintf` function in `yyxz.asp` is called with the attacker-controlled `ID` as input.
5.  Due to the lack of proper bounds checking, the overly long `ID` overflows the stack buffer.
6.  The attacker overwrites adjacent memory on the stack, including the return address.
7.  Upon function return, control is transferred to the attacker-controlled address.
8.  The attacker executes arbitrary code on the device.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary code on the affected D-Link DI-8100 router. This could lead to complete compromise of the device, allowing attackers to intercept network traffic, modify router settings, or use the device as a bot in a botnet. Given that this device is typically deployed on the network perimeter, a successful attack could compromise the internal network.

## Recommendation

*   Apply available patches or firmware updates from D-Link to remediate the `sprintf` stack-based buffer overflow vulnerability (CVE-2026-7851).
*   Monitor web server logs for suspicious requests targeting the `yyxz.asp` file with unusually long `ID` parameters, indicative of potential exploitation attempts.
*   Deploy the Sigma rules provided to detect exploitation attempts in network traffic.
