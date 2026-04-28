---
title: Tenda F456 Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-stack-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-6197) exists in Tenda F456 version 1.0.0.5, allowing remote attackers to execute arbitrary code by manipulating the 'mit_ssid' argument in the '/goform/AdvSetWrlsafeset' file.
date: "2026-04-13T19:16:57Z"
severities:
  - critical
tags:
  - cve-2026-6197
  - buffer-overflow
  - router
  - tenda
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
cves:
  - id: CVE-2026-6197
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6197
  - https://github.com/Litengzheng/vuldb_new/blob/main/F456/vul_114/README.md
  - https://vuldb.com/vuln/357119
rules:
  - title: Tenda F456 Buffer Overflow Attempt
    description: Detects attempts to exploit the stack-based buffer overflow in Tenda F456 via a long mit_ssid parameter
    platform: sigma
    severity: high
    tactics:
      - exploitation
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Tenda F456 Buffer Overflow Exploit
    description: Detects shellcode execution following exploitation of the stack-based buffer overflow in Tenda F456
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A stack-based buffer overflow vulnerability, identified as CVE-2026-6197, has been discovered in Tenda F456 router firmware version 1.0.0.5. The vulnerability resides within the `formWrlsafeset` function of the `/goform/AdvSetWrlsafeset` file. Attackers can exploit this flaw by sending a specially crafted request to the router, specifically manipulating the `mit_ssid` argument. Successful exploitation allows a remote attacker to potentially execute arbitrary code on the device. Publicly available exploits exist, increasing the likelihood of exploitation. This vulnerability poses a significant risk to users of affected Tenda F456 routers, potentially leading to complete device compromise.

## Attack Chain

1.  The attacker identifies a vulnerable Tenda F456 router running firmware version 1.0.0.5.
2.  The attacker crafts a malicious HTTP POST request targeting the `/goform/AdvSetWrlsafeset` endpoint.
3.  The request includes the `mit_ssid` argument with a payload exceeding the expected buffer size.
4.  The web server processes the request and calls the `formWrlsafeset` function.
5.  Due to insufficient bounds checking, the oversized `mit_ssid` value overwrites memory on the stack.
6.  The attacker carefully crafts the overflow to overwrite the return address on the stack.
7.  Upon function return, control is redirected to the attacker-controlled address.
8.  The attacker executes arbitrary code, potentially gaining full control of the router.

## Impact

Successful exploitation of CVE-2026-6197 allows a remote, unauthenticated attacker to execute arbitrary code on the Tenda F456 router. This could lead to a complete compromise of the device, allowing the attacker to modify router settings, intercept network traffic, or use the router as a bot in a larger attack. Given the potential for widespread exploitation due to publicly available exploit code, a significant number of Tenda F456 users could be affected.

## Recommendation

*   Monitor web server logs for suspicious POST requests to `/goform/AdvSetWrlsafeset` with unusually long `mit_ssid` values (see Sigma rule `Tenda F456 Buffer Overflow Attempt`).
*   Deploy the Sigma rule `Tenda F456 Buffer Overflow Exploit` to detect shellcode execution following the overflow.
*   Since there is no mention of a patch, consider replacing the device or isolating it from sensitive networks.
