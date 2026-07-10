---
title: Tenda AC5 Stack-Based Buffer Overflow Vulnerability (CVE-2026-4906)
slug: 2024-01-tenda-ac5-stack-overflow
description: A stack-based buffer overflow vulnerability exists in Tenda AC5 version 15.03.06.47 allowing remote attackers to execute arbitrary code by manipulating the WANT/WANS argument in a POST request to /goform/WizardHandle.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-4906
  - tenda
  - buffer-overflow
  - router
vendors:
  - Tenda
products:
  - Tenda AC5
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4906
  - https://lavender-bicycle-a5a.notion.site/Tenda_AC5_WizardHandle_PPW-32053a41781f80cab094d750d30dc9a8?source=copy_link
  - https://vuldb.com/?id.353657
rules:
  - title: Tenda AC5 Suspicious WizardHandle POST Request
    description: Detects suspicious POST requests to /goform/WizardHandle with potentially malicious WANT/WANS parameters, indicative of CVE-2026-4906 exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Tenda AC5 WizardHandle Buffer Overflow Attempt (WANT)
    description: Detects potential buffer overflow attempts in the Tenda AC5 router by monitoring the length of the WANT parameter in POST requests to /goform/WizardHandle.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Tenda AC5 WizardHandle Buffer Overflow Attempt (WANS)
    description: Detects potential buffer overflow attempts in the Tenda AC5 router by monitoring the length of the WANS parameter in POST requests to /goform/WizardHandle.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 3
---

CVE-2026-4906 is a critical vulnerability affecting Tenda AC5 version 15.03.06.47. This vulnerability is a stack-based buffer overflow located in the `decodePwd` function of the `/goform/WizardHandle` file, specifically within the POST Request Handler component. An unauthenticated, remote attacker can exploit this vulnerability by sending a crafted POST request with a manipulated `WANT` or `WANS` argument. Publicly available exploit code exists, increasing the risk of widespread exploitation. Successful exploitation allows attackers to execute arbitrary code on the affected device, potentially leading to complete system compromise. This poses a significant risk to organizations and home users relying on this Tenda router model.

## Attack Chain

1.  The attacker identifies a vulnerable Tenda AC5 router running firmware version 15.03.06.47.
2.  The attacker crafts a malicious POST request targeting the `/goform/WizardHandle` endpoint.
3.  The POST request includes the `WANT` or `WANS` argument, carefully crafted to cause a buffer overflow in the `decodePwd` function.
4.  The router processes the POST request and calls the `decodePwd` function.
5.  Due to the insufficient bounds checking in `decodePwd`, the oversized `WANT` or `WANS` argument overwrites adjacent memory on the stack.
6.  The attacker overwrites critical data, such as the return address, with a malicious address pointing to injected shellcode.
7.  The `decodePwd` function returns, but instead of returning to the legitimate caller, it jumps to the attacker-controlled shellcode.
8.  The shellcode executes with the privileges of the web server process, allowing the attacker to perform arbitrary actions on the system, such as gaining a reverse shell or modifying router settings.

## Impact

Successful exploitation of CVE-2026-4906 allows a remote attacker to execute arbitrary code on the vulnerable Tenda AC5 router. This could lead to complete compromise of the device, allowing the attacker to modify router settings, intercept network traffic, or use the router as a pivot point to attack other devices on the network. Given the widespread use of Tenda routers in home and small business environments, this vulnerability poses a significant risk to a large number of users.

## Recommendation

*   Monitor web server logs for POST requests to `/goform/WizardHandle` with unusually long `WANT` or `WANS` parameters. Deploy the Sigma rule `Tenda AC5 Suspicious WizardHandle POST Request` to detect this activity.
*   Apply any available patches or firmware updates released by Tenda to address CVE-2026-4906.
*   Consider deploying a web application firewall (WAF) with rules to block requests that exploit buffer overflow vulnerabilities, mitigating the risk even if a patch is not immediately available.
*   Implement network segmentation to limit the impact of a compromised router on other devices on the network.
