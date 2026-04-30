---
title: Tenda AC7 Stack-Based Buffer Overflow in SetSysTimeCfg
slug: 2026-03-tenda-ac7-overflow
description: A stack-based buffer overflow vulnerability exists in Tenda AC7 version 15.03.06.44 within the fromSetSysTime function of the /goform/SetSysTimeCfg component's POST Request Handler, allowing a remote attacker to potentially execute arbitrary code by manipulating the 'Time' argument.
date: "2026-03-27T20:16:38Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - buffer-overflow
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4974
  - https://lavender-bicycle-a5a.notion.site/Tenda-AC7-fromSetSysTime-32153a41781f801c95b0f8a53eaa9a1f?source=copy_link
  - https://vuldb.com/?id.353861
rules:
  - title: Detect Suspiciously Long Time Parameter in Tenda AC7 SetSysTimeCfg
    description: Detects POST requests to /goform/SetSysTimeCfg with an unusually long Time parameter, indicative of a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Processes Spawned by Webserver After Potential Tenda AC7 Overflow
    description: Detects processes spawned by the webserver after a potential buffer overflow exploit, indicating code execution.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A stack-based buffer overflow vulnerability has been identified in Tenda AC7 router firmware, specifically version 15.03.06.44. The vulnerability resides in the `fromSetSysTime` function within the `/goform/SetSysTimeCfg` component, which handles POST requests. A remote attacker can exploit this flaw by crafting a malicious POST request with an overly long `Time` argument, causing a buffer overflow on the stack. Publicly available exploits exist, increasing the risk of exploitation. Successful exploitation could lead to arbitrary code execution on the device, potentially granting the attacker complete control over the router. This is a critical vulnerability due to the ease of remote exploitation and the potential for significant impact.

## Attack Chain

1. Attacker identifies a Tenda AC7 router running firmware version 15.03.06.44.
2. Attacker crafts a POST request targeting the `/goform/SetSysTimeCfg` endpoint.
3. The POST request includes the `Time` argument, set to a string exceeding the expected buffer size.
4. The `fromSetSysTime` function processes the `Time` argument without proper bounds checking.
5. The overly long `Time` argument overflows the stack buffer during the copy operation.
6. The buffer overflow overwrites critical data on the stack, including the return address.
7. The attacker controls the overwritten return address, redirecting execution flow to malicious code.
8. The attacker gains arbitrary code execution on the router, potentially leading to complete device compromise.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary code on the affected Tenda AC7 router. This can lead to a variety of malicious outcomes, including complete device compromise, modification of router settings (DNS, firewall rules), interception of network traffic, and use of the router as a botnet node. Given the widespread use of Tenda routers, a large number of devices could be vulnerable, potentially impacting home users and small businesses.

## Recommendation

*   Apply available patches or firmware updates provided by Tenda to address CVE-2026-4974.
*   Monitor webserver logs for POST requests to `/goform/SetSysTimeCfg` with abnormally long `Time` parameters, using the Sigma rule provided below.
*   Implement rate limiting on the `/goform/SetSysTimeCfg` endpoint to mitigate brute-force attempts to exploit the vulnerability.
*   Deploy the Sigma rule to detect processes spawned by the webserver after the exploit is triggered.
