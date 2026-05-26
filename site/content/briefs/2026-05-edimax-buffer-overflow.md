---
title: Edimax BR-6675nD Buffer Overflow Vulnerability (CVE-2026-9403)
slug: 2026-05-edimax-buffer-overflow
description: A buffer overflow vulnerability exists in Edimax BR-6675nD version 1.12 within the formWlSiteSurvey function of the /goform/formWlSiteSurvey file, triggered by manipulating the selSSID argument in a POST request, enabling remote exploitation.
date: "2026-05-26T14:06:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer overflow
  - cve-2026-9403
  - edimax
  - router
vendors:
  - Edimax
products:
  - BR-6675nD 1.12
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-9403
    cvss: 8.8
    epss: 0.00041
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9403
  - https://lavender-bicycle-a5a.notion.site/EDIMAX-BR-6675nD-formWlSiteSurvey-34b53a41781f80608091f104f17e1e9b?source=copy_link
  - https://vuldb.com/submit/811566
  - https://vuldb.com/vuln/365384
  - https://vuldb.com/vuln/365384/cti
rules:
  - title: Detect CVE-2026-9403 Exploitation Attempt
    description: Detects CVE-2026-9403 exploitation attempt — HTTP POST to /goform/formWlSiteSurvey with an overly long selSSID value indicating a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9403 - Suspicious process from vulnerable device
    description: Detects CVE-2026-9403 exploitation leading to unexpected process execution on a network device
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A buffer overflow vulnerability, CVE-2026-9403, has been identified in Edimax BR-6675nD router firmware version 1.12. The flaw resides in the `formWlSiteSurvey` function located within the `/goform/formWlSiteSurvey` file. This function, responsible for handling POST requests related to Wi-Fi site surveys, is susceptible to a buffer overflow when processing the `selSSID` argument. A remote attacker can exploit this vulnerability to potentially execute arbitrary code on the device. Public exploits are available, increasing the risk of exploitation. The vendor was notified but has not responded.

## Attack Chain

1.  The attacker sends a crafted HTTP POST request to the `/goform/formWlSiteSurvey` endpoint on the Edimax BR-6675nD router.
2.  The POST request includes the `selSSID` argument, designed to carry the selected SSID for the site survey.
3.  The attacker provides an overly long string as the value for the `selSSID` argument, exceeding the buffer size allocated for it.
4.  The `formWlSiteSurvey` function processes the POST request without proper bounds checking on the length of the `selSSID` value.
5.  The excessive data written to the `selSSID` buffer overflows into adjacent memory regions on the stack.
6.  The overflow overwrites critical data structures, such as return addresses or function pointers, stored on the stack.
7.  When the `formWlSiteSurvey` function attempts to return, the overwritten return address is used, redirecting execution flow to an attacker-controlled address.
8.  The attacker gains arbitrary code execution on the router, potentially leading to full device compromise.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary code on the Edimax BR-6675nD router. This can lead to complete compromise of the device, potentially allowing the attacker to gain control of the network, intercept traffic, or use the router as a foothold for further attacks within the network. Given the widespread use of such routers, a large number of devices could be at risk.

## Recommendation

*   Monitor webserver logs for POST requests to `/goform/formWlSiteSurvey` with abnormally long `selSSID` values to detect potential exploitation attempts (see Sigma rule `Detect CVE-2026-9403 Exploitation Attempt`).
*   Implement network intrusion detection system (IDS) rules to identify and block malicious POST requests targeting this endpoint.
*   Since no patch is available, consider replacing the affected device with a more secure alternative if possible.
*   Monitor for unexpected processes or network connections originating from Edimax BR-6675nD devices, as this may indicate successful exploitation.
