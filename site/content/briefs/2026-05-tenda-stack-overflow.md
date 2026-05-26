---
title: Tenda F1202 Stack-Based Buffer Overflow Vulnerability (CVE-2026-9429)
slug: 2026-05-tenda-stack-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-9429) exists in Tenda F1202 version 1.2.0.20(408) within the formWrlExtraSet function of the /goform/WrlExtraSet file, allowing a remote attacker to execute arbitrary code by manipulating the delno argument; a public exploit is available.
date: "2026-05-26T14:08:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - stack-based buffer overflow
  - router vulnerability
  - cve-2026-9429
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
  - id: CVE-2026-9429
    cvss: 8.8
    epss: 0.00046
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9429
  - https://github.com/Litengzheng/vuldb_new2/blob/main/F1202/vul_31/README.md
  - https://vuldb.com/submit/813912
  - https://vuldb.com/vuln/365410
  - https://vuldb.com/vuln/365410/cti
  - https://www.tenda.com.cn/
rules:
  - title: Detect Suspiciously Long delno Parameter in Tenda Routers
    description: Detects HTTP POST requests to /goform/WrlExtraSet with an unusually long delno parameter, potentially indicating a buffer overflow attempt on Tenda routers (CVE-2026-9429).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
  - title: Detect Access to Tenda Configuration File
    description: Detects access to the /goform/WrlExtraSet file on Tenda routers, potentially indicating attempts to exploit CVE-2026-9429.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-9429 is a stack-based buffer overflow vulnerability affecting Tenda F1202 devices running firmware version 1.2.0.20(408). The vulnerability resides in the `formWrlExtraSet` function within the `/goform/WrlExtraSet` file. A remote attacker can exploit this vulnerability by crafting a malicious request that manipulates the `delno` argument, leading to arbitrary code execution on the affected device. This is particularly concerning as a public exploit is available, increasing the likelihood of exploitation. Successful exploitation allows attackers to compromise the router and potentially gain access to the local network.

## Attack Chain

1.  The attacker identifies a Tenda F1202 router running firmware version 1.2.0.20(408).
2.  The attacker crafts a malicious HTTP request targeting the `/goform/WrlExtraSet` endpoint.
3.  Within the HTTP request, the attacker includes the `delno` argument with a value exceeding the buffer's capacity in the `formWrlExtraSet` function.
4.  The vulnerable `formWrlExtraSet` function processes the `delno` argument without proper bounds checking.
5.  The excessive data provided in the `delno` argument overwrites the stack.
6.  The attacker injects malicious code into the overflowed buffer.
7.  The injected code is executed, granting the attacker control over the device.
8.  The attacker can then perform actions such as modifying router settings, intercepting network traffic, or establishing a backdoor for persistent access.

## Impact

Successful exploitation of CVE-2026-9429 allows an attacker to gain complete control over the Tenda F1202 router. This can lead to a variety of malicious activities, including data theft, denial of service, and the establishment of a persistent foothold on the network. Given the availability of a public exploit, organizations and individuals using the affected Tenda F1202 router are at significant risk.

## Recommendation

*   Apply available patches or firmware updates from Tenda to address CVE-2026-9429.
*   Monitor web server logs for suspicious POST requests to `/goform/WrlExtraSet` with abnormally long `delno` arguments, using the Sigma rule `Detect Suspiciously Long delno Parameter in Tenda Routers`.
*   Implement network intrusion detection systems (IDS) rules to detect and block exploitation attempts targeting CVE-2026-9429.
*   Review and restrict access to the router's management interface to trusted IP addresses only.
*   Enable logging on the Tenda router and forward logs to a SIEM for centralized monitoring and analysis.
