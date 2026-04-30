---
title: Tenda CX12L Router Stack-Based Buffer Overflow Vulnerability (CVE-2026-5686)
slug: 2026-04-tenda-cx12l-stack-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-5686) exists in the Tenda CX12L router version 16.03.53.12, allowing remote attackers to potentially execute arbitrary code by manipulating the 'page' argument in the `/goform/RouteStatic` endpoint.
date: "2026-04-06T22:16:24Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-5686
  - tenda
  - router
  - stack-based buffer overflow
  - remote code execution
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5686
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5686
  - https://github.com/cve-a/lvdan/issues/4
  - https://vuldb.com/vuln/355513
rules:
  - title: Detect Suspiciously Long Page Parameter in Tenda Router Request
    description: Detects HTTP POST requests to /goform/RouteStatic with an unusually long 'page' parameter, which could indicate a buffer overflow attempt related to CVE-2026-5686.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP 404 Errors After Exploitation Attempt on /goform/RouteStatic
    description: After a successful exploit, the attacker may attempt to verify execution by triggering a 404 error. This rule detects such behavior.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5686 is a critical vulnerability affecting Tenda CX12L routers running firmware version 16.03.53.12. This stack-based buffer overflow is located in the `fromRouteStatic` function within the `/goform/RouteStatic` file. A remote, unauthenticated attacker can exploit this vulnerability by sending a crafted request with a malicious `page` argument. Publicly available exploit code exists, increasing the risk of widespread exploitation. Successful exploitation could lead to arbitrary code execution, potentially allowing attackers to gain full control of the affected router. This poses a significant risk to home and small business networks using the vulnerable device.

## Attack Chain

1.  The attacker identifies a Tenda CX12L router running firmware version 16.03.53.12.
2.  The attacker sends a crafted HTTP POST request to `/goform/RouteStatic`.
3.  The request includes a `page` argument with a string exceeding the buffer size allocated to the `fromRouteStatic` function.
4.  The oversized `page` argument overwrites adjacent memory on the stack, including the return address.
5.  When the `fromRouteStatic` function returns, it attempts to jump to the overwritten return address controlled by the attacker.
6.  The attacker's payload, injected via the overflowed buffer, is executed with the privileges of the `httpd` process.
7.  The attacker gains remote code execution on the router.
8.  The attacker can then use the compromised router as a foothold for further attacks, such as network reconnaissance, lateral movement, or data exfiltration.

## Impact

Successful exploitation of CVE-2026-5686 allows a remote attacker to execute arbitrary code on the affected Tenda CX12L router. This could lead to a complete compromise of the device, enabling attackers to modify router settings, intercept network traffic, or use the router as a proxy for malicious activities. Given the widespread use of Tenda routers in home and small business networks, this vulnerability could have a significant impact, potentially affecting thousands of users. A successful attack could lead to data breaches, service disruptions, and further compromise of connected devices within the network.

## Recommendation

*   Apply available patches or firmware updates provided by Tenda to address CVE-2026-5686.
*   Monitor web server logs for suspicious POST requests to `/goform/RouteStatic` with unusually long `page` parameters, using the provided Sigma rule.
*   Implement network intrusion detection systems (IDS) to detect and block exploit attempts targeting this vulnerability.
*   Restrict access to the router's administrative interface to trusted networks or IP addresses to limit the attack surface.
*   Regularly review router configurations and security settings to ensure they align with best practices.
