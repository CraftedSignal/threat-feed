---
title: Totolink N300RH Buffer Overflow Vulnerability in setUpgradeFW Function
slug: 2026-05-totolink-n300rh-buffer-overflow
description: A buffer overflow vulnerability exists in Totolink N300RH 3.2.4-B20220812 within the setUpgradeFW function, allowing remote attackers to execute arbitrary code by manipulating the FileName argument in a POST request to /cgi-bin/cstecgi.cgi.
date: "2026-05-04T10:16:00Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - buffer-overflow
  - router
  - cve-2026-7748
vendors:
  - Totolink
products:
  - N300RH 3.2.4-B20220812
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7748
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7748
  - https://lavender-bicycle-a5a.notion.site/TOTOLINK-N300RH-setUpgradeFW-34553a41781f80abb1d1c627d7ff4329?pvs=73
  - https://vuldb.com/submit/807202
  - https://vuldb.com/vuln/360923
  - https://vuldb.com/vuln/360923/cti
  - https://www.totolink.net/
rules:
  - title: Detect POST Request to cstecgi.cgi with Excessive FileName Length
    description: Detects POST requests to the /cgi-bin/cstecgi.cgi endpoint with an unusually long FileName parameter, potentially indicating a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect suspicious POST request cstecgi.cgi
    description: Detects POST requests to /cgi-bin/cstecgi.cgi with abnormal characters in the FileName parameter
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A buffer overflow vulnerability, identified as CVE-2026-7748, affects Totolink N300RH router version 3.2.4-B20220812. The vulnerability resides within the `setUpgradeFW` function of the `/cgi-bin/cstecgi.cgi` file, which handles POST requests. Publicly available exploit code enables attackers to remotely trigger a buffer overflow by manipulating the `FileName` argument in a crafted POST request. Successful exploitation allows arbitrary code execution, potentially leading to full device compromise. This vulnerability is significant due to the wide deployment of Totolink routers in home and small office environments.

## Attack Chain

1.  Attacker identifies a vulnerable Totolink N300RH router (version 3.2.4-B20220812) accessible over the network.
2.  Attacker crafts a malicious POST request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3.  The POST request includes the `FileName` argument, specifically crafted to exceed the buffer size allocated within the `setUpgradeFW` function.
4.  The vulnerable `setUpgradeFW` function processes the POST request without proper bounds checking on the `FileName` argument.
5.  The excessively long `FileName` value overwrites adjacent memory locations on the stack or heap, corrupting critical data or control flow structures.
6.  The attacker injects malicious code into the overflowing data.
7.  The corrupted data leads to the execution of the attacker-controlled code, granting the attacker control over the device.
8.  The attacker can then use this access to perform actions like modifying router settings, eavesdropping on network traffic, or establishing a persistent backdoor.

## Impact

Successful exploitation of this buffer overflow vulnerability allows a remote attacker to execute arbitrary code on the affected Totolink N300RH device. This could result in a complete compromise of the router, allowing the attacker to eavesdrop on network traffic, modify router configurations, and potentially use the compromised device as a foothold for further attacks on the internal network. Given the prevalence of Totolink routers, a large number of devices could be at risk if this vulnerability is actively exploited.

## Recommendation

*   Monitor web server logs for POST requests to `/cgi-bin/cstecgi.cgi` with unusually long `FileName` parameters to detect potential exploitation attempts.
*   Implement network intrusion detection system (IDS) rules to detect and block suspicious POST requests targeting the `/cgi-bin/cstecgi.cgi` endpoint.
*   Since there are no actionable IOCs in the source and firmware updates are unavailable, consider network segmentation to limit the impact of compromised devices.
