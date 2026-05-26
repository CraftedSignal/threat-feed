---
title: Tenda F1202 Stack-Based Buffer Overflow Vulnerability (CVE-2026-9428)
slug: 2026-05-tenda-stack-overflow
description: A remote stack-based buffer overflow vulnerability (CVE-2026-9428) exists in the fromPPTPUserSetting function of the /goform/PPTPUserSetting file in Tenda F1202 version 1.2.0.20(408), allowing attackers to potentially execute arbitrary code.
date: "2026-05-26T14:07:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - stack-buffer-overflow
  - tenda
vendors:
  - Tenda
products:
  - F1202 1.2.0.20(408)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-9428
    cvss: 8.8
    epss: 0.00046
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9428
  - https://github.com/Litengzheng/vuldb_new2/blob/main/F1202/vul_29/README.md
  - https://vuldb.com/submit/813911
  - https://vuldb.com/vuln/365409
  - https://vuldb.com/vuln/365409/cti
  - https://www.tenda.com.cn/
rules:
  - title: Detect CVE-2026-9428 Exploitation Attempt via PPTPUserSetting
    description: Detects CVE-2026-9428 exploitation attempt — HTTP POST request to the PPTPUserSetting endpoint, indicative of a potential exploit attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9428 - Overflow Argument
    description: Detects CVE-2026-9428 exploitation attempt — detects abnormally large delno parameters which may indicate a buffer overflow attempt
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

A stack-based buffer overflow vulnerability, CVE-2026-9428, has been identified in Tenda F1202 router version 1.2.0.20(408). The vulnerability lies within the `fromPPTPUserSetting` function of the `/goform/PPTPUserSetting` file. A remote attacker can exploit this vulnerability by manipulating the `delno` argument, leading to a buffer overflow. Public exploits are available, increasing the risk of exploitation. This vulnerability allows unauthenticated remote attackers to potentially execute arbitrary code on the affected device.

## Attack Chain

1.  Attacker identifies a Tenda F1202 router running firmware version 1.2.0.20(408).
2.  Attacker sends a crafted HTTP request to the `/goform/PPTPUserSetting` endpoint.
3.  The HTTP request includes a malicious `delno` argument designed to overflow the buffer.
4.  The `fromPPTPUserSetting` function processes the request without proper bounds checking.
5.  The `delno` argument overflows the stack buffer.
6.  The overflow overwrites critical function return addresses.
7.  The function returns to an attacker-controlled address.
8.  Attacker gains arbitrary code execution on the router.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary code on the Tenda F1202 router. This can lead to complete system compromise, including unauthorized access to the network, data exfiltration, and denial of service. Given the availability of public exploits, vulnerable devices are at immediate risk of exploitation.

## Recommendation

*   Apply the Sigma rule `Detect CVE-2026-9428 Exploitation Attempt via PPTPUserSetting` to detect suspicious requests to the vulnerable endpoint.
*   Apply the Sigma rule `Detect CVE-2026-9428 - Overflow Argument` to identify requests containing unusually long arguments which may point to the vulnerability
*   Monitor web server logs for HTTP POST requests to `/goform/PPTPUserSetting` (see rule `Detect CVE-2026-9428 Exploitation Attempt via PPTPUserSetting` logsource).
