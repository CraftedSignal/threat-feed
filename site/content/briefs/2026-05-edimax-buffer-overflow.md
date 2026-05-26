---
title: Edimax EW-7438RPn Stack-Based Buffer Overflow Vulnerability (CVE-2026-9461)
slug: 2026-05-edimax-buffer-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-9461) exists in the formRadius function of the /goform/formRadius file in Edimax EW-7438RPn version 1.31, which can be exploited remotely by manipulating the submit-url argument.
date: "2026-05-26T14:12:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-9461
  - buffer-overflow
  - network-device
vendors:
  - Edimax
products:
  - EW-7438RPn 1.31
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-9461
    cvss: 8.8
    epss: 0.00041
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9461
  - https://github.com/wudipjq/my_vuln/blob/main/Edimax/vuln_14/14.md
  - https://vuldb.com/submit/813898
  - https://vuldb.com/vuln/365442
  - https://vuldb.com/vuln/365442/cti
rules:
  - title: Detect CVE-2026-9461 Exploitation Attempt via Long Submit-URL
    description: Detects CVE-2026-9461 exploitation attempts by monitoring for abnormally long submit-url parameters in requests to /goform/formRadius.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9461 Exploitation - POST to formRadius
    description: Detects CVE-2026-9461 exploitation — Monitors for POST requests to the /goform/formRadius endpoint, potentially indicating an exploitation attempt.
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

A stack-based buffer overflow vulnerability, CVE-2026-9461, has been identified in Edimax EW-7438RPn version 1.31. The vulnerability resides in the `formRadius` function within the `/goform/formRadius` file. An attacker can exploit this vulnerability by manipulating the `submit-url` argument, leading to arbitrary code execution. The attack can be initiated remotely, making it a significant threat. Public disclosure of the exploit increases the likelihood of exploitation. The vendor was notified but has not responded.

## Attack Chain

1.  Attacker sends a crafted HTTP request to the Edimax EW-7438RPn device.
2.  The HTTP request targets the `/goform/formRadius` endpoint.
3.  The request includes the `submit-url` argument with a payload exceeding the buffer size.
4.  The `formRadius` function processes the `submit-url` argument without proper bounds checking.
5.  The excessive data overwrites the stack, including the return address.
6.  The overwritten return address points to attacker-controlled code.
7.  Upon function return, control is transferred to the attacker's code.
8.  Attacker gains arbitrary code execution on the device, potentially leading to full system compromise.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary code on the affected Edimax EW-7438RPn device. This could lead to complete device compromise, allowing the attacker to control the device, steal sensitive information, or use it as a bot in a larger attack. Given that this is a network device often used in home and small business environments, a successful attack could have significant consequences for the affected users.

## Recommendation

*   Monitor web server logs for requests to `/goform/formRadius` with abnormally long `submit-url` arguments using the "Detect CVE-2026-9461 Exploitation Attempt via Long Submit-URL" Sigma rule.
*   Inspect network traffic for unusually large HTTP POST requests targeting the `/goform/formRadius` endpoint.
*   Implement input validation and sanitization on the Edimax EW-7438RPn device to prevent buffer overflows.
