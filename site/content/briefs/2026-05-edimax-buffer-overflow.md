---
title: Edimax BR-6428NS Buffer Overflow Vulnerability (CVE-2026-8776)
slug: 2026-05-edimax-buffer-overflow
description: A buffer overflow vulnerability (CVE-2026-8776) exists in Edimax BR-6428NS version 1.10 due to improper handling of the pptpUserName argument in the formPPTPSetup function, allowing a remote attacker to potentially execute arbitrary code.
date: "2026-05-18T02:19:13Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - cve
  - buffer overflow
  - network device
  - router
vendors:
  - Edimax
products:
  - BR-6428NS 1.10
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-8776
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8776
  - https://lavender-bicycle-a5a.notion.site/EDIMAX-BR-6428NS-formPPTPSetup-34b53a41781f8074a88af068842b599e?source=copy_link
  - https://vuldb.com/submit/811531
  - https://vuldb.com/vuln/364401
  - https://vuldb.com/vuln/364401/cti
rules:
  - title: Detect CVE-2026-8776 Exploitation Attempt — Malicious PPTP Username
    description: Detects CVE-2026-8776 exploitation attempt — unusually long pptpUserName values in POST requests to formPPTPSetup, indicating a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-8776 Exploitation Attempt — Suspicious Characters in PPTP Username
    description: Detects CVE-2026-8776 exploitation attempt — pptpUserName values in POST requests to formPPTPSetup containing suspicious characters indicative of code injection.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A buffer overflow vulnerability, identified as CVE-2026-8776, has been discovered in Edimax BR-6428NS router version 1.10. The vulnerability resides within the POST Request Handler component, specifically in the `/goform/formPPTPSetup` file and its `formPPTPSetup` function. Successful exploitation of this vulnerability allows a remote attacker to potentially execute arbitrary code. The vulnerability stems from the inadequate handling of the `pptpUserName` argument, which, when manipulated, leads to a buffer overflow condition. Publicly available exploit code exists, increasing the risk of active exploitation. The vendor was notified but has not responded.

## Attack Chain

1. The attacker identifies an Edimax BR-6428NS router version 1.10 with a publicly accessible web interface.
2. The attacker crafts a malicious HTTP POST request targeting the `/goform/formPPTPSetup` endpoint.
3. The crafted POST request includes the `pptpUserName` parameter with a value exceeding the expected buffer size.
4. The webserver receives the POST request and passes the `pptpUserName` argument to the `formPPTPSetup` function.
5. The `formPPTPSetup` function copies the overly long `pptpUserName` into a fixed-size buffer without proper bounds checking.
6. This buffer overflow overwrites adjacent memory regions, potentially including critical program data or execution pointers.
7. The attacker gains the ability to execute arbitrary code on the router.
8. The attacker could then use this access to modify router settings, intercept network traffic, or establish a persistent backdoor.

## Impact

Successful exploitation of CVE-2026-8776 allows a remote attacker to execute arbitrary code on the Edimax BR-6428NS router. This could allow the attacker to gain full control of the device, potentially compromising the network it serves. Given the lack of vendor response and the availability of public exploits, affected devices are at significant risk. This is especially impactful for small businesses and home users who often lack sophisticated security measures.

## Recommendation

*   Deploy the Sigma rule "Detect CVE-2026-8776 Exploitation Attempt — Malicious PPTP Username" to detect exploitation attempts (see below).
*   Monitor web server logs for POST requests to `/goform/formPPTPSetup` with unusually long `pptpUserName` values.
*   Consider using a web application firewall (WAF) to filter out malicious requests targeting the vulnerable endpoint.
*   If possible, disable the PPTP functionality of the router if not required.
*   While a patch is unavailable, network segmentation can limit the impact of a compromised device.
