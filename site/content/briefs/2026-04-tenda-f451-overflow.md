---
title: Tenda F451 Router Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-f451-overflow
description: Tenda F451 router version 1.0.0.7 is vulnerable to a stack-based buffer overflow in the frmL7ProtForm function, enabling remote attackers to execute arbitrary code by manipulating the 'page' argument.
date: "2026-04-12T08:16:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-6122
  - buffer-overflow
  - router
  - tenda
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6122
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6122
rules:
  - title: Detect Tenda F451 Buffer Overflow Attempt
    description: Detects attempts to exploit the stack-based buffer overflow vulnerability (CVE-2026-6122) in Tenda F451 routers by monitoring for requests to the /goform/L7Prot endpoint with excessively long 'page' parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda F451 POST Request to L7Prot
    description: Detects POST requests to the /goform/L7Prot endpoint which may indicate command execution or exploitation attempts.
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

A critical stack-based buffer overflow vulnerability has been identified in Tenda F451 router version 1.0.0.7. The vulnerability resides within the `frmL7ProtForm` function of the `/goform/L7Prot` component, specifically within the `httpd` service. A remote attacker can exploit this flaw by crafting a malicious request targeting the `page` argument. Successful exploitation allows the attacker to execute arbitrary code on the device. Publicly available exploit code exists, increasing the risk of widespread exploitation. This vulnerability poses a significant threat to affected devices, potentially leading to full device compromise.

## Attack Chain

1.  Attacker identifies a vulnerable Tenda F451 router running firmware version 1.0.0.7.
2.  Attacker crafts a malicious HTTP GET or POST request targeting the `/goform/L7Prot` endpoint.
3.  The malicious request includes the `page` argument with a payload exceeding the buffer size allocated for it within the `frmL7ProtForm` function.
4.  The `httpd` service processes the request without proper bounds checking on the `page` argument.
5.  The oversized payload overflows the stack buffer during the execution of the `frmL7ProtForm` function.
6.  The buffer overflow overwrites adjacent memory regions on the stack, including the return address.
7.  The attacker-controlled return address redirects execution to attacker-supplied code or a return-oriented programming (ROP) chain.
8.  The attacker executes arbitrary code on the router, potentially gaining full control of the device.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary code on the affected Tenda F451 router. This can lead to a complete compromise of the device, allowing the attacker to modify router settings, intercept network traffic, or use the device as a bot in a botnet. Given the availability of public exploits, vulnerable devices are at high risk of compromise. The number of potentially affected devices is substantial, as the Tenda F451 is a widely used router model.

## Recommendation

*   Monitor web server logs for requests to `/goform/L7Prot` with unusually long `page` parameters, deploying the Sigma rule `Detect Tenda F451 Buffer Overflow Attempt` to identify potential exploitation attempts.
*   Since no patch is available, consider replacing the Tenda F451 1.0.0.7 with a more secure router or firewall solution.
*   Implement network segmentation to limit the impact of a compromised router on other network devices.
*   Disable remote administration access to the router to reduce the attack surface.
