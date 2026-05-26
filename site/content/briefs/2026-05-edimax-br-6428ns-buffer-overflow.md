---
title: Edimax BR-6428NS Buffer Overflow Vulnerability (CVE-2026-9294)
slug: 2026-05-edimax-br-6428ns-buffer-overflow
description: A buffer overflow vulnerability (CVE-2026-9294) exists in the formWanTcpipSetup function of the /goform/formWanTcpipSetup file in Edimax BR-6428NS 1.10, which can be triggered by a remote attacker manipulating the pppUserName argument via a POST request, potentially leading to arbitrary code execution.
date: "2026-05-26T13:34:59Z"
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
  - BR-6428NS 1.10
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-9294
    cvss: 8.8
    epss: 0.00015
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9294
  - https://lavender-bicycle-a5a.notion.site/EDIMAX-BR-6428NS-formWanTcpipSetup-34b53a41781f80049b27db22e62fd8fd?source=copy_link
  - https://vuldb.com/submit/811533
  - https://vuldb.com/vuln/365241
  - https://vuldb.com/vuln/365241/cti
rules:
  - title: Detects CVE-2026-9294 Exploitation Attempt - Long pppUserName in POST Request
    description: Detects CVE-2026-9294 exploitation attempt — Monitors web server logs for POST requests to /goform/formWanTcpipSetup with abnormally long pppUserName values, indicating a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects suspicious POST request to /goform/formWanTcpipSetup
    description: Detects potential exploitation attempts targeting Edimax routers by monitoring POST requests to the /goform/formWanTcpipSetup endpoint.
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

A buffer overflow vulnerability, identified as CVE-2026-9294, has been discovered in Edimax BR-6428NS router firmware version 1.10. This flaw resides within the `formWanTcpipSetup` function located in the `/goform/formWanTcpipSetup` file, specifically affecting the POST Request Handler component. Successful exploitation of this vulnerability allows a remote attacker to cause a buffer overflow by manipulating the `pppUserName` argument. Publicly available exploit code exists, increasing the risk of active exploitation. The vendor was notified of the vulnerability but did not respond.

## Attack Chain

1.  The attacker sends a crafted HTTP POST request to the `/goform/formWanTcpipSetup` endpoint on the Edimax BR-6428NS router.
2.  The POST request includes the `pppUserName` argument with a payload exceeding the expected buffer size.
3.  The `formWanTcpipSetup` function processes the POST request without proper bounds checking on the `pppUserName` argument.
4.  The oversized `pppUserName` value overwrites adjacent memory regions, leading to a buffer overflow.
5.  The attacker carefully crafts the overflow payload to overwrite critical data, such as function return addresses.
6.  When the `formWanTcpipSetup` function returns, it attempts to execute code at the overwritten return address.
7.  The attacker gains control of the execution flow and can inject and execute arbitrary code on the router.

## Impact

Successful exploitation of CVE-2026-9294 can lead to arbitrary code execution on the Edimax BR-6428NS router. This can allow an attacker to gain complete control of the device, potentially leading to modification of router settings, interception of network traffic, or use of the router as a pivot point for further attacks on the local network. Given the availability of public exploits, unpatched devices are at significant risk.

## Recommendation

*   Apply available firmware updates for Edimax BR-6428NS if they become available.
*   Monitor web server logs for suspicious POST requests to `/goform/formWanTcpipSetup` with unusually long `pppUserName` values using the Sigma rule provided.
*   Implement network intrusion detection systems (IDS) rules to detect and block exploit attempts targeting CVE-2026-9294.
*   Restrict access to the router's web management interface from the public internet where possible.
