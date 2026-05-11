---
title: D-Link DCS-935L HNAP Service Buffer Overflow (CVE-2026-8260)
slug: 2026-05-dlink-dcs-935l-buffer-overflow
description: D-Link DCS-935L devices up to version 1.10.01 are vulnerable to a remote buffer overflow (CVE-2026-8260) in the HNAP service that can be triggered by manipulating the AdminPassword argument in the SetDeviceSettings function.
date: "2026-05-11T02:17:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - buffer-overflow
  - cve
  - d-link
vendors:
  - D-Link
products:
  - DCS-935L (<= 1.10.01)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-8260
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8260
rules:
  - title: Detect CVE-2026-8260 Exploitation Attempt - Long AdminPassword
    description: Detects CVE-2026-8260 exploitation attempt - monitors POST requests to the HNAP service with an overly long AdminPassword, which may indicate a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

D-Link DCS-935L devices running firmware up to version 1.10.01 are susceptible to a buffer overflow vulnerability (CVE-2026-8260) affecting the HNAP (Home Network Administration Protocol) service. The vulnerability resides within the `SetDeviceSettings` function located in `/web/cgi-bin/hnap/hnap_service`. An attacker can remotely exploit this vulnerability by sending a specially crafted request that overflows the buffer allocated for the `AdminPassword` argument. Publicly available exploits exist, increasing the risk of exploitation. This vulnerability poses a significant threat to device confidentiality, integrity, and availability, as successful exploitation can lead to arbitrary code execution and full device compromise.

## Attack Chain

1.  Attacker identifies a D-Link DCS-935L device running vulnerable firmware (<= 1.10.01) accessible over the network.
2.  Attacker crafts a malicious HTTP request targeting the `/web/cgi-bin/hnap/hnap_service` endpoint.
3.  The crafted request includes a `SetDeviceSettings` action with an `AdminPassword` argument containing a payload exceeding the expected buffer size.
4.  The device processes the request, calling the `SetDeviceSettings` function.
5.  Due to insufficient bounds checking, the oversized `AdminPassword` argument overwrites adjacent memory on the stack, including the return address.
6.  The `SetDeviceSettings` function completes and attempts to return execution to the overwritten return address.
7.  The attacker-controlled return address redirects execution to a malicious code payload injected within the `AdminPassword` argument or elsewhere in memory.
8.  The attacker gains arbitrary code execution on the device, potentially leading to full device compromise.

## Impact

Successful exploitation of CVE-2026-8260 can lead to complete compromise of the affected D-Link DCS-935L device. This includes the ability to execute arbitrary code, gain unauthorized access to device settings and sensitive information, and potentially use the device as a bot in a larger attack. Given the widespread use of these devices, a large number of users are potentially at risk.

## Recommendation

*   Apply available patches or firmware updates from D-Link to mitigate CVE-2026-8260 on affected DCS-935L devices (reference: affected_products).
*   Monitor web server logs for suspicious POST requests to `/web/cgi-bin/hnap/hnap_service` with unusually long `AdminPassword` values in the request body (reference: rules).
*   Deploy the Sigma rule to detect potential exploitation attempts against the HNAP service (reference: rules).
