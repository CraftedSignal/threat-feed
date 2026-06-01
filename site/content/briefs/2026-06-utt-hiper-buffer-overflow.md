---
title: UTT HiPER 1200GW Stack-Based Buffer Overflow Vulnerability (CVE-2026-10293)
slug: 2026-06-utt-hiper-buffer-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-10293) exists in UTT HiPER 1200GW up to version 2.5.3-170306 due to the strcpy function in /goform/formFireWall, allowing remote exploitation via manipulation of the Profile argument.
date: "2026-06-01T22:19:25Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - cve
  - buffer-overflow
  - router
  - network-device
vendors:
  - UTT
products:
  - HiPER 1200GW (<= 2.5.3-170306)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-10293
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10293
  - https://github.com/yuezhaoshanmu/cve/blob/main/2.md
  - https://vuldb.com/cve/CVE-2026-10293
  - https://vuldb.com/submit/826416
  - https://vuldb.com/vuln/367586
  - https://vuldb.com/vuln/367586/cti
rules:
  - title: Detect CVE-2026-10293 Exploitation Attempt - Long Profile Parameter
    description: Detects CVE-2026-10293 exploitation attempt — Monitors web server logs for suspicious POST requests to /goform/formFireWall with unusually long Profile parameters, indicative of a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-10293 Exploitation Attempt - Abnormal HTTP Status Code
    description: Detects CVE-2026-10293 exploitation attempt — Detects abnormal server responses (5xx errors) following POST requests to /goform/formFireWall with 'Profile=' parameters, potentially indicating a server crash due to buffer overflow.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A stack-based buffer overflow vulnerability, tracked as CVE-2026-10293, has been identified in UTT HiPER 1200GW devices up to version 2.5.3-170306. The vulnerability lies within the `strcpy` function in the `/goform/formFireWall` file. An attacker can exploit this flaw by manipulating the `Profile` argument, leading to potential remote code execution. Publicly available exploit code exists, increasing the risk of active exploitation. This vulnerability poses a significant threat to organizations using affected UTT HiPER devices, potentially allowing unauthorized access and control over the network.

## Attack Chain

1.  Attacker identifies a vulnerable UTT HiPER 1200GW device with version 2.5.3-170306 or earlier.
2.  Attacker sends a crafted HTTP request to the `/goform/formFireWall` endpoint.
3.  The HTTP request includes a malicious payload in the `Profile` argument, designed to cause a buffer overflow.
4.  The `strcpy` function copies the attacker-controlled `Profile` argument into a fixed-size buffer on the stack.
5.  Due to insufficient bounds checking, the copy operation overwrites adjacent memory regions on the stack.
6.  The attacker carefully crafts the payload to overwrite the return address, redirecting execution flow.
7.  Upon function return, execution jumps to the attacker-controlled address.
8.  Attacker gains remote code execution on the device, potentially allowing for complete system compromise.

## Impact

Successful exploitation of CVE-2026-10293 can lead to complete compromise of the UTT HiPER 1200GW device. This could allow attackers to gain unauthorized access to the network, steal sensitive information, or use the device as a foothold for further attacks within the network. Given the publicly available exploit, the risk of widespread exploitation is elevated.

## Recommendation

*   Apply available patches or upgrade to a non-vulnerable version of UTT HiPER 1200GW firmware to remediate CVE-2026-10293.
*   Monitor web server logs for suspicious POST requests to `/goform/formFireWall` with overly long `Profile` parameters, triggering the detection rule "Detect CVE-2026-10293 Exploitation Attempt - Long Profile Parameter".
*   Implement network intrusion detection systems (IDS) rules to detect and block exploit attempts targeting CVE-2026-10293.
