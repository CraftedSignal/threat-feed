---
title: Tenda AC6 Stack-Based Buffer Overflow Vulnerability
slug: 2026-03-tenda-ac6-overflow
description: A stack-based buffer overflow vulnerability in Tenda AC6 version 15.03.05.16 allows remote attackers to execute arbitrary code by manipulating the WANT/WANS argument in the /goform/WizardHandle POST request handler.
date: "2026-03-27T17:16:30Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2026-4960
  - buffer-overflow
  - tenda
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4960
  - https://lavender-bicycle-a5a.notion.site/Tenda-AC6-WizardHandle-32053a41781f800eb05feb16885747f7?source=copy_link
  - https://vuldb.com/?ctiid.353837
  - https://vuldb.com/?id.353837
  - https://vuldb.com/?submit.777616
  - https://www.tenda.com.cn/
rules:
  - title: Detect Tenda AC6 WizardHandle Buffer Overflow Attempt
    description: Detects suspicious POST requests to /goform/WizardHandle with excessively long WANT or WANS parameters, indicative of a buffer overflow attempt (CVE-2026-4960).
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Exploitation Attempt via HTTP POST Request to /goform/WizardHandle
    description: Detects attempts to exploit a vulnerability by sending a POST request to /goform/WizardHandle.
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

A critical stack-based buffer overflow vulnerability has been identified in Tenda AC6 router firmware version 15.03.05.16. The vulnerability, tracked as CVE-2026-4960, resides within the `fromWizardHandle` function of the `/goform/WizardHandle` component, which handles POST requests. A remote attacker can exploit this vulnerability by sending a crafted POST request with a manipulated `WANT` or `WANS` argument, leading to arbitrary code execution on the device. Public exploit code is available, increasing the risk of widespread exploitation. This vulnerability poses a significant threat, potentially allowing attackers to gain complete control over vulnerable routers and compromise connected networks.

## Attack Chain

1.  Attacker identifies a Tenda AC6 router running firmware version 15.03.05.16.
2.  The attacker crafts a malicious POST request targeting the `/goform/WizardHandle` endpoint.
3.  Within the POST request, the attacker manipulates the `WANT` or `WANS` argument to inject a payload exceeding the buffer size.
4.  The router processes the POST request, passing the attacker-controlled input to the vulnerable `fromWizardHandle` function.
5.  The overflow occurs when the `fromWizardHandle` function copies the attacker-supplied data into a fixed-size buffer on the stack without proper bounds checking.
6.  The injected payload overwrites adjacent memory locations on the stack, including the return address.
7.  When the `fromWizardHandle` function returns, it jumps to the attacker-controlled address.
8.  The attacker gains arbitrary code execution on the router, potentially leading to complete system compromise.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to gain complete control of the affected Tenda AC6 router. This can lead to a variety of malicious outcomes, including network hijacking, DNS poisoning, interception of network traffic, deployment of malware, and the creation of botnets. Given the widespread use of Tenda routers in home and small business networks, a large number of devices are potentially vulnerable. The CVSS v3.1 score of 8.8 reflects the high severity of this vulnerability.

## Recommendation

*   Apply any available firmware updates from Tenda to patch CVE-2026-4960.
*   Monitor web server logs for suspicious POST requests to `/goform/WizardHandle` with abnormally long `WANT` or `WANS` parameters using the Sigma rule provided below.
*   Implement network intrusion detection system (NIDS) rules to detect exploit attempts targeting the `/goform/WizardHandle` endpoint.
*   Restrict access to the router's web interface from the public internet where possible to reduce the attack surface.
