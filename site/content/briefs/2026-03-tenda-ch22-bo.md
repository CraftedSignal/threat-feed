---
title: Tenda CH22 Stack-Based Buffer Overflow Vulnerability (CVE-2026-5204)
slug: 2026-03-tenda-ch22-bo
description: A stack-based buffer overflow vulnerability (CVE-2026-5204) exists in the Tenda CH22 1.0.0.1 router, allowing remote attackers to execute arbitrary code by manipulating the webSiteId argument in the formWebTypeLibrary function.
date: "2026-03-31T16:16:35Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-5204
  - tenda
  - buffer-overflow
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5204
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5204
  - https://github.com/Litengzheng/vuldb_new/blob/main/CH22/vul_49/README.md
  - https://vuldb.com/vuln/354332
rules:
  - title: Tenda CH22 WebSiteId Buffer Overflow Attempt
    description: Detects attempts to exploit the CVE-2026-5204 vulnerability in Tenda CH22 routers by overflowing the webSiteId parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: WebSiteId Length Detection in Tenda CH22
    description: Detects unusually long webSiteId parameters, potentially indicating a buffer overflow attempt.
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

CVE-2026-5204 describes a critical stack-based buffer overflow vulnerability affecting Tenda CH22 router version 1.0.0.1. The vulnerability resides within the `formWebTypeLibrary` function in the `/goform/webtypelibrary` file, which handles web-based parameter input. An attacker can exploit this vulnerability by sending a specially crafted HTTP request to the router, manipulating the `webSiteId` argument to overwrite the stack buffer. This allows for arbitrary code execution on the device. Given the router's role as a network gateway, successful exploitation can lead to complete compromise of the device and potentially the entire network behind it. The availability of a public exploit increases the risk of widespread exploitation.

## Attack Chain

1. The attacker identifies a vulnerable Tenda CH22 router running firmware version 1.0.0.1.
2. The attacker crafts a malicious HTTP POST request targeting the `/goform/webtypelibrary` endpoint.
3. The crafted request includes the `webSiteId` parameter with a payload exceeding the expected buffer size, triggering the stack-based buffer overflow in the `formWebTypeLibrary` function.
4. The overflow overwrites critical data on the stack, including the return address.
5. The overwritten return address is replaced with the address of malicious code injected into the payload or a pre-existing code location within the router's firmware (Return-Oriented Programming - ROP).
6. The `formWebTypeLibrary` function returns, transferring control to the attacker-controlled code.
7. The attacker's code executes, granting the attacker control over the device.
8. The attacker can then use this control to further compromise the network or disrupt services.

## Impact

Successful exploitation of CVE-2026-5204 allows a remote attacker to execute arbitrary code on the vulnerable Tenda CH22 router. This can lead to complete control of the device, enabling the attacker to intercept network traffic, modify DNS settings, create VPNs, or launch further attacks on devices within the network. Given that routers are essential network devices, a successful attack can have a significant impact, affecting all connected devices and potentially exposing sensitive data.

## Recommendation

*   Apply available firmware updates for Tenda CH22 routers immediately to patch CVE-2026-5204.
*   Deploy the Sigma rule `Tenda-CH22-WebSiteId-Buffer-Overflow` to detect exploitation attempts targeting the vulnerable endpoint.
*   Monitor web server logs for suspicious POST requests to `/goform/webtypelibrary` with unusually long `webSiteId` parameters, as indicated by `WebSiteId_Length_Detection` Sigma rule.
*   Implement network segmentation to limit the impact of a potential router compromise.
