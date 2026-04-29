---
title: Tenda F451 Router Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-rce
description: A stack-based buffer overflow vulnerability in the Tenda F451 router (version 1.0.0.7) allows remote attackers to execute arbitrary code by manipulating the 'page' argument in the fromRouteStatic function of the /goform/RouteStatic file.
date: "2026-04-10T00:16:36Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - tenda
  - router
  - buffer_overflow
  - rce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-5989
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5989
  - https://github.com/Jimi-Lab/cve/issues/5
  - https://vuldb.com/vuln/356543
rules:
  - title: Detect Tenda F451 Exploit Attempt
    description: Detects potential exploit attempts against the Tenda F451 router by monitoring requests to the /goform/RouteStatic endpoint with unusually long 'page' arguments, which may indicate a buffer overflow attack.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Detect High HTTP Status Codes After RouteStatic Access
    description: Detects potential exploit attempts by identifying elevated HTTP status codes after accessing the vulnerable RouteStatic endpoint.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, identified as CVE-2026-5989, affects the Tenda F451 router, specifically version 1.0.0.7. The vulnerability lies within the `fromRouteStatic` function of the `/goform/RouteStatic` file. By manipulating the `page` argument, a remote attacker can trigger a stack-based buffer overflow, potentially leading to arbitrary code execution. Publicly available exploit code exists, increasing the risk of exploitation. This vulnerability poses a significant threat as it allows unauthenticated remote attackers to compromise the router, potentially leading to network disruption, data theft, or use of the device in botnet activities.

## Attack Chain

1.  The attacker identifies a vulnerable Tenda F451 router (version 1.0.0.7) exposed to the internet.
2.  The attacker crafts a malicious HTTP request targeting the `/goform/RouteStatic` endpoint.
3.  The request includes a `page` argument with a payload designed to overflow the stack buffer in the `fromRouteStatic` function.
4.  The vulnerable `fromRouteStatic` function processes the malicious `page` argument without proper bounds checking.
5.  The buffer overflow overwrites critical data on the stack, including the return address.
6.  Upon function return, control is redirected to the attacker-controlled memory region.
7.  The attacker executes arbitrary code injected into the overflowed buffer, such as downloading and executing a reverse shell.
8.  The attacker gains remote access to the router, potentially allowing further exploitation or network compromise.

## Impact

Successful exploitation of CVE-2026-5989 allows an attacker to gain complete control of the Tenda F451 router. This can lead to a variety of damaging outcomes, including denial-of-service attacks against the local network, interception of network traffic, modification of router settings, and the potential use of the compromised router as a node in a botnet. Given the widespread use of Tenda routers in home and small business environments, a large number of devices could be at risk if this vulnerability is actively exploited.

## Recommendation

*   Monitor web server logs for requests to `/goform/RouteStatic` containing abnormally long `page` arguments, as this is indicative of potential exploit attempts. Deploy the Sigma rule `Detect Tenda F451 Exploit Attempt` to detect these malicious requests.
*   Implement rate limiting on requests to the `/goform/RouteStatic` endpoint to mitigate potential denial-of-service attacks.
*   Since there is no patch available, consider replacing vulnerable Tenda F451 routers with more secure devices from other vendors.
