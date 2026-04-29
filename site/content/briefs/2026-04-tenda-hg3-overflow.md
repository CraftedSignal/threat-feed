---
title: Tenda HG3 v2.0 Stack-Based Buffer Overflow in formUploadConfig
slug: 2026-04-tenda-hg3-overflow
description: A stack-based buffer overflow vulnerability in the formUploadConfig function of Tenda HG3 v2.0's /boaform/formIPv6Routing file allows remote attackers to execute arbitrary code by manipulating the destNet argument.
date: "2026-04-28T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2026-7151
  - buffer-overflow
  - tenda
  - router
vendors:
  - Tenda
products:
  - HG3
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
cves:
  - id: CVE-2026-7151
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7151
  - https://vuldb.com/vuln/359750
  - https://vuldb.com/submit/802058
  - https://www.notion.so/33e0c75766a88041bd86d3810994a541
rules:
  - title: Detect Tenda HG3 formUploadConfig Buffer Overflow Attempt
    description: Detects attempts to exploit the stack-based buffer overflow in Tenda HG3's formUploadConfig function by monitoring for abnormally long destNet parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda HG3 formUploadConfig POST Request
    description: Detects POST requests to Tenda HG3's formUploadConfig function. Monitor for unusual IPs or request patterns.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stack-based buffer overflow vulnerability has been identified in Tenda HG3 version 2.0. The vulnerability exists within the `formUploadConfig` function of the `/boaform/formIPv6Routing` file. A remote attacker can exploit this by manipulating the `destNet` argument, potentially leading to arbitrary code execution on the device. The vulnerability, identified as CVE-2026-7151, has a publicly available exploit, increasing the risk of exploitation. This poses a significant threat to users of Tenda HG3 v2.0 routers, potentially allowing attackers to gain unauthorized access and control over the device. The CVSS v3.1 score is rated as 8.8 (HIGH).

## Attack Chain

1.  Attacker identifies a Tenda HG3 v2.0 router with default or known credentials, or no authentication at all.
2.  The attacker sends a crafted HTTP POST request to `/boaform/formIPv6Routing`.
3.  The request targets the `formUploadConfig` function.
4.  The `destNet` argument within the HTTP POST data is manipulated with a string exceeding the buffer size.
5.  The `formUploadConfig` function processes the oversized `destNet` argument without proper bounds checking.
6.  This causes a stack-based buffer overflow, overwriting adjacent memory regions on the stack.
7.  The attacker gains arbitrary code execution on the device by overwriting the return address or other critical data on the stack.
8.  The attacker can then leverage this to gain full control of the device, potentially modifying settings, injecting malware, or using it as part of a botnet.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary code on the affected Tenda HG3 v2.0 router. This could lead to complete compromise of the device, allowing the attacker to monitor network traffic, change router settings, or use the device as a launchpad for further attacks against other devices on the network. Given the potential for widespread exploitation due to the publicly available exploit, a large number of Tenda HG3 v2.0 users are at risk.

## Recommendation

*   Monitor web server logs for unusual POST requests to `/boaform/formIPv6Routing` with excessively long `destNet` parameters to detect potential exploit attempts (see example Sigma rule below).
*   Implement rate limiting for requests to `/boaform/formIPv6Routing` to mitigate brute-force exploitation attempts.
*   Apply available patches or firmware updates from Tenda to address CVE-2026-7151 on vulnerable HG3 2.0 devices.
*   Consider deploying a web application firewall (WAF) rule to filter out malicious requests targeting the `destNet` parameter in `/boaform/formIPv6Routing`.
