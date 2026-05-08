---
title: Tenda CX12L Stack-Based Buffer Overflow Vulnerability (CVE-2026-8138)
slug: 2026-05-tenda-cx12l-bo
description: Tenda CX12L router version 16.03.53.12 is vulnerable to a stack-based buffer overflow in the formSetPPTPServer function of /goform/SetPptpServerCfg, allowing remote attackers to execute arbitrary code.
date: "2026-05-08T05:16:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - buffer-overflow
  - tenda
vendors:
  - Tenda
products:
  - CX12L
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-8138
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8138
  - https://github.com/cve-a/lvdan/issues/6
  - https://vuldb.com/vuln/361927
rules:
  - title: Detect CVE-2026-8138 Exploitation Attempt — Tenda CX12L Buffer Overflow
    description: Detects CVE-2026-8138 exploitation attempt — a POST request to /goform/SetPptpServerCfg with an unusually long parameter value, indicative of a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Suspicious HTTP POST to SetPptpServerCfg Endpoint
    description: Detects suspicious HTTP POST requests to the SetPptpServerCfg endpoint, potentially indicating an exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

A stack-based buffer overflow vulnerability, identified as CVE-2026-8138, affects Tenda CX12L router with firmware version 16.03.53.12. The vulnerability resides in the `formSetPPTPServer` function within the `/goform/SetPptpServerCfg` file. The vulnerability was reported on 2026-05-08, and a proof-of-concept exploit is publicly available. Successful exploitation could allow a remote attacker to execute arbitrary code on the affected device, potentially leading to a full system compromise. This vulnerability poses a significant risk to users of the affected Tenda router model.

## Attack Chain

1.  The attacker identifies a Tenda CX12L router running firmware version 16.03.53.12 exposed to the internet.
2.  The attacker crafts a malicious HTTP request targeting the `/goform/SetPptpServerCfg` endpoint.
3.  The crafted request includes an overly long string as input to the `formSetPPTPServer` function.
4.  The `formSetPPTPServer` function copies the attacker-supplied string into a fixed-size buffer on the stack without proper bounds checking.
5.  The buffer overflow overwrites adjacent stack memory, including the function's return address.
6.  When the `formSetPPTPServer` function returns, it attempts to jump to the overwritten return address, now controlled by the attacker.
7.  The attacker-controlled return address points to shellcode injected as part of the malicious HTTP request.
8.  The shellcode executes with the privileges of the affected process, allowing the attacker to execute arbitrary commands on the router.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary code on the Tenda CX12L router. This could allow the attacker to gain complete control over the device, potentially leading to the theft of sensitive information (such as Wi-Fi passwords), modification of router settings (such as DNS servers), or the use of the router as a bot in a larger botnet. Given the widespread use of Tenda routers, this vulnerability could impact a significant number of users.

## Recommendation

*   Deploy the Sigma rule "Detect CVE-2026-8138 Exploitation Attempt — Tenda CX12L Buffer Overflow" to your SIEM to detect exploitation attempts targeting the vulnerable endpoint.
*   Apply the Sigma rule "Detect Suspicious HTTP POST to SetPptpServerCfg Endpoint" to identify unusual activity.
*   Monitor web server logs for POST requests to `/goform/SetPptpServerCfg` with abnormally long parameter values to identify potential exploitation attempts.
