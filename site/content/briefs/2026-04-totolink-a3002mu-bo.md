---
title: Totolink A3002MU Router Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-totolink-a3002mu-bo
description: A stack-based buffer overflow vulnerability (CVE-2026-6194) exists in the Totolink A3002MU B20211125.1046 router firmware, specifically affecting the `/boafrm/formWlanSetup` component's HTTP request handler, which allows remote attackers to execute arbitrary code by manipulating the `wan-url` argument.
date: "2026-04-14T12:00:00Z"
severities:
  - critical
tags:
  - cve-2026-6194
  - buffer-overflow
  - totolink
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.001
    technique_name: 'Remote Services: RDP'
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
cves:
  - id: CVE-2026-6194
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6194
  - https://github.com/zhuchan770/vulnerability/blob/main/A3002MU/formWlanSetup/ToToLinkA3002MU%20formWlanSetup%20339996b67c9780caafb2d351dfd8a889.md
  - https://vuldb.com/vuln/357116
rules:
  - title: Detect Suspicious WAN-URL Parameter Length
    description: Detects HTTP requests to /boafrm/formWlanSetup with an unusually long wan-url parameter, potentially indicating a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - exploitation
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A3002MU HTTP Request
    description: Detects HTTP requests with the string Totolink and A3002MU, helpful in identifying possible exploit attempts.
    platform: sigma
    severity: informational
    tactics:
      - reconnaissance
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-6194 describes a stack-based buffer overflow vulnerability present in Totolink A3002MU router firmware version B20211125.1046. The vulnerability resides within the HTTP Request Handler, specifically in the `sub_410188` function of the `/boafrm/formWlanSetup` file. A remote attacker can exploit this vulnerability by crafting a malicious HTTP request that manipulates the `wan-url` argument, leading to arbitrary code execution on the device. Publicly available exploit code increases the…
