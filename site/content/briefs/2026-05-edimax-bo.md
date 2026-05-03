---
title: Edimax BR-6208AC Buffer Overflow Vulnerability
slug: 2026-05-edimax-bo
description: A buffer overflow vulnerability exists in Edimax BR-6208AC devices (<= 1.02) via manipulation of the pptpDfGateway argument in the /goform/setWAN endpoint, potentially allowing remote attackers to execute arbitrary code.
date: "2026-05-03T07:16:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - buffer overflow
  - cve-2026-7685
  - router
  - webserver
vendors:
  - Edimax
products:
  - BR-6208AC (<= 1.02)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7685
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7685
  - https://tzh00203.notion.site/Edimax-BR-6428nC-v1-16-setWAN-pptpDfGateway-Stack-Overflow-33db5c52018a80c1835dd4fab4b6c7f2
  - https://vuldb.com/vuln/360844
rules:
  - title: Detect Edimax BR-6208AC setWAN Buffer Overflow Attempt
    description: Detects potential buffer overflow attempts on Edimax BR-6208AC routers by monitoring for suspicious POST requests to the /goform/setWAN endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Long pptpDfGateway Parameter
    description: Detects unusually long pptpDfGateway parameters in web requests, potentially indicating a buffer overflow attempt on Edimax devices.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A buffer overflow vulnerability, CVE-2026-7685, has been identified in Edimax BR-6208AC routers up to version 1.02. The vulnerability resides within the `/goform/setWAN` file, specifically related to the `pptpDfGateway` argument. Successful exploitation of this flaw could allow a remote attacker to execute arbitrary code or cause a denial-of-service condition. Publicly available exploits exist, increasing the risk of widespread exploitation. The vendor was notified but has not responded. Given the ease of exploitation and the potential for significant impact, this vulnerability poses a critical threat to affected devices.

## Attack Chain

1.  Attacker identifies an Edimax BR-6208AC router with firmware version 1.02 or earlier exposed to the internet.
2.  The attacker crafts a malicious HTTP POST request targeting the `/goform/setWAN` endpoint.
3.  Within the POST request, the attacker includes the `pptpDfGateway` argument, injecting a payload exceeding the buffer's expected size.
4.  The router's web server processes the malicious request without proper input validation on the size of the `pptpDfGateway` argument.
5.  The oversized payload overwrites adjacent memory regions on the stack, potentially including return addresses or other critical data.
6.  When the function attempts to return, it jumps to an address controlled by the attacker, leading to arbitrary code execution.
7.  The attacker executes commands to gain control of the device, potentially installing malware or modifying router settings.

## Impact

Successful exploitation of this vulnerability can lead to complete compromise of the Edimax BR-6208AC router. An attacker could leverage this access to perform a variety of malicious activities, including eavesdropping on network traffic, injecting malicious code into web pages served by the router, or using the router as a bot in a larger botnet. Given the availability of public exploits, unpatched devices are at immediate risk of compromise.

## Recommendation

*   Deploy the Sigma rule `Detect Edimax BR-6208AC setWAN Buffer Overflow Attempt` to identify exploitation attempts in web server logs.
*   Inspect web server logs for POST requests to `/goform/setWAN` containing unusually long `pptpDfGateway` parameters, as detected by the Sigma rule `Detect Long pptpDfGateway Parameter`.
*   Apply appropriate network segmentation to limit the blast radius of compromised devices and prevent lateral movement.
