---
title: D-Link DIR-605L Router Buffer Overflow Vulnerability (CVE-2026-5980)
slug: 2026-04-dlink-dir605l-buffer-overflow
description: A buffer overflow vulnerability exists in the D-Link DIR-605L router version 2.13B01, allowing a remote attacker to execute arbitrary code by manipulating the `curTime` argument in the `formSetMACFilter` function.
date: "2026-04-09T21:16:14Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve
  - buffer_overflow
  - router
  - d-link
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
    technique_id: T1040
    technique_name: Network Sniffing
cves:
  - id: CVE-2026-5980
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5980
  - https://lavender-bicycle-a5a.notion.site/D-Link-DIR-605L-formSetMACFilter-33153a41781f807c8fb4c3a75f7b555e?source=copy_link
  - https://vuldb.com/vuln/356534
rules:
  - title: Detect D-Link DIR-605L Buffer Overflow Attempt
    description: Detects POST requests to /goform/formSetMACFilter with abnormally long curTime parameters, indicative of a buffer overflow attempt in D-Link DIR-605L routers.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect D-Link DIR-605L User-Agent
    description: Detects HTTP requests with the default D-Link DIR-605L User-Agent string, which may indicate reconnaissance or exploitation attempts.
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

CVE-2026-5980 is a critical buffer overflow vulnerability affecting the D-Link DIR-605L router, specifically version 2.13B01. The vulnerability resides in the `formSetMACFilter` function within the `/goform/formSetMACFilter` component's POST Request Handler. A remote attacker can exploit this by sending a crafted POST request with a malicious `curTime` argument, leading to a buffer overflow. Exploit code is publicly available. Due to the product's end-of-life status, no patch is available, making unpatched devices highly vulnerable. This allows for potential remote code execution and complete compromise of the device.

## Attack Chain

1.  The attacker identifies a vulnerable D-Link DIR-605L router (version 2.13B01) exposed to the internet.
2.  The attacker crafts a malicious POST request targeting the `/goform/formSetMACFilter` endpoint.
3.  Within the POST request, the attacker includes the `curTime` parameter, injecting a string exceeding the buffer's expected size.
4.  The router's `formSetMACFilter` function processes the POST request without proper bounds checking on the `curTime` argument.
5.  The oversized `curTime` string overflows the buffer, overwriting adjacent memory regions.
6.  The attacker carefully crafts the overflow to overwrite critical data, such as return addresses or function pointers.
7.  When the `formSetMACFilter` function attempts to return, the overwritten return address is used, redirecting execution to attacker-controlled code.
8.  The attacker gains arbitrary code execution on the router, potentially installing malware, changing configurations, or using the device for further malicious activities.

## Impact

Successful exploitation of CVE-2026-5980 allows a remote attacker to gain complete control over the vulnerable D-Link DIR-605L router. Given that the affected product is no longer supported, a large number of legacy routers remain vulnerable. Attackers can leverage compromised routers to establish botnets, conduct man-in-the-middle attacks, or gain unauthorized access to internal networks connected to the router. The lack of patches elevates the severity, as affected users have no direct mitigation available other than replacing the device.

## Recommendation

*   Deploy the Sigma rule `Detect D-Link DIR-605L Buffer Overflow Attempt` to identify malicious POST requests targeting the `/goform/formSetMACFilter` endpoint on D-Link DIR-605L devices.
*   Implement network segmentation to isolate potentially vulnerable D-Link DIR-605L routers to limit the impact of a successful compromise.
*   If possible, replace D-Link DIR-605L routers (version 2.13B01) with newer, supported devices to eliminate the vulnerability.
