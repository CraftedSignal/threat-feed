---
title: Edimax BR-6675nD Buffer Overflow Vulnerability (CVE-2026-9382)
slug: 2026-05-edimax-buffer-overflow
description: A buffer overflow vulnerability exists in Edimax BR-6675nD 1.12 within the formPPTPSetup function of the POST Request Handler component, allowing a remote attacker to execute arbitrary code by manipulating the pptpUserName argument in a POST request to /goform/formPPTPSetup.
date: "2026-05-26T13:48:31Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - buffer-overflow
  - router
  - cve
vendors:
  - Edimax
products:
  - BR-6675nD 1.12
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-9382
    cvss: 8.8
    epss: 0.00041
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9382
  - https://lavender-bicycle-a5a.notion.site/EDIMAX-BR-6675nD-formPPTPSetup-34b53a41781f80e6ab7df78a28ffe568?source=copy_link
  - https://vuldb.com/submit/811560
  - https://vuldb.com/vuln/365345
  - https://vuldb.com/vuln/365345/cti
rules:
  - title: Edimax BR-6675nD Suspicious PPTP Username Length
    description: Detects CVE-2026-9382 exploitation — HTTP POST requests to the /goform/formPPTPSetup endpoint with a suspiciously long pptpUserName, indicating a potential buffer overflow attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Edimax BR-6675nD formPPTPSetup Access
    description: Detects access to the Edimax BR-6675nD formPPTPSetup endpoint, which is vulnerable to CVE-2026-9382.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A buffer overflow vulnerability, CVE-2026-9382, has been identified in Edimax BR-6675nD version 1.12. The vulnerability resides in the `formPPTPSetup` function of the `/goform/formPPTPSetup` endpoint, specifically within the POST Request Handler. Successful exploitation allows a remote attacker to cause a buffer overflow by manipulating the `pptpUserName` argument in a POST request. Publicly available exploits exist, increasing the risk of active exploitation. The vendor has not responded to disclosure attempts, potentially leaving users vulnerable. This vulnerability allows an attacker to gain unauthorized access to the device.

## Attack Chain

1.  The attacker identifies an Edimax BR-6675nD router running firmware version 1.12.
2.  The attacker crafts a malicious HTTP POST request targeting the `/goform/formPPTPSetup` endpoint.
3.  Within the POST request, the `pptpUserName` parameter is set to a string exceeding the buffer's expected size.
4.  The router's web server receives the crafted POST request and passes the `pptpUserName` argument to the `formPPTPSetup` function.
5.  The `formPPTPSetup` function copies the oversized `pptpUserName` string into a fixed-size buffer without proper bounds checking.
6.  The buffer overflow corrupts adjacent memory regions, potentially overwriting critical data or code pointers.
7.  The overwritten code pointer is executed, allowing the attacker to inject and execute arbitrary code on the device.
8.  The attacker gains control of the device, potentially enabling further malicious activities such as configuration changes, network sniffing, or use as a botnet node.

## Impact

Successful exploitation of CVE-2026-9382 leads to arbitrary code execution on the Edimax BR-6675nD device. This compromises the device's confidentiality, integrity, and availability. An attacker could potentially gain complete control of the router, intercept network traffic, modify DNS settings, or use the compromised device as part of a botnet. Given the widespread use of these routers in home and small office environments, a successful attack could impact a significant number of users.

## Recommendation

*   Monitor web server logs for POST requests to `/goform/formPPTPSetup` with unusually long `pptpUserName` parameters using the provided Sigma rule `Edimax BR-6675nD Suspicious PPTP Username Length`.
*   Implement rate limiting on the `/goform/formPPTPSetup` endpoint to mitigate brute-force exploitation attempts.
*   Since the vendor is unresponsive, consider alternative router solutions until a patch becomes available.
*   Deploy the Sigma rule `Edimax BR-6675nD formPPTPSetup Access` to detect access to the vulnerable endpoint.
