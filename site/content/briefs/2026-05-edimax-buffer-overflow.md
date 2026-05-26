---
title: Edimax BR-6675nD Buffer Overflow Vulnerability (CVE-2026-9401)
slug: 2026-05-edimax-buffer-overflow
description: A buffer overflow vulnerability (CVE-2026-9401) exists in Edimax BR-6675nD version 1.12 within the formWanTcpipSetup function, allowing a remote attacker to execute arbitrary code by manipulating the pppUserName argument in a POST request.
date: "2026-05-26T14:06:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - buffer_overflow
  - router
  - edimax
vendors:
  - Edimax
products:
  - BR-6675nD 1.12
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-9401
    cvss: 8.8
    epss: 0.00041
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9401
  - https://lavender-bicycle-a5a.notion.site/EDIMAX-BR-6675nD-formWanTcpipSetup-34b53a41781f8020ab30c8ca204ab15d?source=copy_link
  - https://vuldb.com/submit/811563
  - https://vuldb.com/vuln/365382
  - https://vuldb.com/vuln/365382/cti
rules:
  - title: Detect CVE-2026-9401 Exploitation Attempt — Malicious pppUserName Length
    description: Detects CVE-2026-9401 exploitation attempt — Monitors the length of the pppUserName parameter in POST requests to /goform/formWanTcpipSetup for excessive values, indicating a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9401 Exploitation Attempt —  /goform/formWanTcpipSetup POST Request
    description: Detects CVE-2026-9401 exploitation attempt by monitoring for POST requests to the vulnerable /goform/formWanTcpipSetup endpoint.
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

A buffer overflow vulnerability, CVE-2026-9401, has been identified in Edimax BR-6675nD router version 1.12. The vulnerability resides within the `formWanTcpipSetup` function of the `/goform/formWanTcpipSetup` file, specifically related to handling the `pppUserName` argument within a POST request. Successful exploitation allows remote attackers to execute arbitrary code due to insufficient bounds checking. Public exploits are available, increasing the risk of widespread exploitation. The vendor was contacted regarding the vulnerability but did not respond.

## Attack Chain

1.  Attacker identifies an Edimax BR-6675nD router version 1.12 exposed to the internet.
2.  The attacker crafts a malicious POST request targeting the `/goform/formWanTcpipSetup` endpoint.
3.  Within the POST request, the attacker includes the `pppUserName` parameter with a value exceeding the expected buffer size.
4.  The router's web server processes the POST request and passes the oversized `pppUserName` value to the `formWanTcpipSetup` function.
5.  The `formWanTcpipSetup` function attempts to copy the oversized `pppUserName` into a fixed-size buffer without proper bounds checking.
6.  This buffer overflow overwrites adjacent memory regions, potentially including critical program data or function pointers.
7.  The attacker manipulates the overwritten data to redirect program execution to attacker-controlled code.
8.  The attacker gains arbitrary code execution on the router, potentially leading to complete system compromise.

## Impact

Successful exploitation of this buffer overflow vulnerability (CVE-2026-9401) allows a remote, unauthenticated attacker to execute arbitrary code on the affected Edimax BR-6675nD router. This could lead to a full compromise of the device, allowing the attacker to modify router settings, intercept network traffic, or use the router as a bot in a larger attack. Given the widespread use of Edimax routers, a successful campaign could impact numerous home and small business networks.

## Recommendation

*   Deploy the Sigma rule "Detect CVE-2026-9401 Exploitation Attempt — Malicious pppUserName Length" to identify potentially malicious POST requests targeting the vulnerable endpoint.
*   Monitor web server logs for POST requests to `/goform/formWanTcpipSetup` and review the length of the `pppUserName` parameter.
*   Consider blocking or rate-limiting traffic to the `/goform/formWanTcpipSetup` endpoint from suspicious IP addresses (reference the Sigma rule for detection logic).
