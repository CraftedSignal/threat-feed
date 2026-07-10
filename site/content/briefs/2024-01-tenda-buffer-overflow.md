---
title: Tenda F451 Stack-Based Buffer Overflow Vulnerability (CVE-2026-5990)
slug: 2024-01-tenda-buffer-overflow
description: A stack-based buffer overflow vulnerability exists in Tenda F451 1.0.0.7 within the fromSafeEmailFilter function of the /goform/SafeEmailFilter file, which can be exploited remotely by manipulating the 'page' argument, leading to potential arbitrary code execution.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - tenda
  - buffer-overflow
  - router
  - cve-2026-5990
  - webserver
vendors:
  - Tenda
products:
  - Tenda F451
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1057
    technique_name: Process Discovery
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-5990
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5990
  - https://github.com/Jimi-Lab/cve/issues/8
  - https://vuldb.com/submit/792861
  - https://vuldb.com/vuln/356544
  - https://vuldb.com/vuln/356544/cti
  - https://www.tenda.com.cn/
rules:
  - title: Detect Suspicious URI Filter Page Parameter
    description: Detects requests to /goform/SafeEmailFilter with an unusually long page parameter, indicative of a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - exploitation
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Webserver Spawning Processes
    description: Detects unexpected processes being spawned from the web server, which may indicate code execution from the webserver.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical stack-based buffer overflow vulnerability, identified as CVE-2026-5990, has been discovered in Tenda F451 version 1.0.0.7. The vulnerability resides within the `fromSafeEmailFilter` function of the `/goform/SafeEmailFilter` file. Successful exploitation allows a remote attacker to execute arbitrary code on the affected device by manipulating the `page` argument. Publicly available exploit code exists, increasing the risk of widespread exploitation. This vulnerability poses a significant threat to organizations and individuals using the affected Tenda F451 router, potentially enabling complete device compromise and network intrusion.

## Attack Chain

1.  Attacker identifies a Tenda F451 router version 1.0.0.7 exposed to the internet.
2.  The attacker crafts a malicious HTTP request targeting the `/goform/SafeEmailFilter` endpoint.
3.  The HTTP request includes a `page` argument containing a payload exceeding the buffer size allocated for it within the `fromSafeEmailFilter` function.
4.  The `fromSafeEmailFilter` function processes the crafted HTTP request without proper bounds checking.
5.  The oversized payload overwrites adjacent memory on the stack, including critical program data and return addresses.
6.  Upon function return, the overwritten return address redirects execution flow to attacker-controlled code.
7.  The attacker gains arbitrary code execution on the Tenda F451 router.
8.  The attacker pivots to other devices on the network, establishes persistence, or exfiltrates sensitive data.

## Impact

Successful exploitation of CVE-2026-5990 allows a remote attacker to gain complete control of the affected Tenda F451 router. This can lead to a variety of malicious activities, including data theft, device hijacking for botnet inclusion, and lateral movement to other devices on the network. Given the widespread use of Tenda routers in home and small business environments, a large number of devices are potentially vulnerable. The potential damage includes loss of sensitive information, disruption of network services, and compromised devices being used for further malicious activities.

## Recommendation

*   Monitor web server logs for requests to `/goform/SafeEmailFilter` containing abnormally long `page` parameters. Deploy the Sigma rule `DetectSuspiciousURIFilterPageParameter` to identify potential exploitation attempts.
*   Implement rate limiting on requests to the `/goform/SafeEmailFilter` endpoint to mitigate brute-force exploitation attempts.
*   Contact Tenda support and request a security patch for CVE-2026-5990.
*   Monitor for unexpected process execution originating from the router's web server process using the `DetectWebserverSpawningProcesses` Sigma rule.
