---
title: Edimax EW-7438RPn Stack-Based Buffer Overflow Vulnerability (CVE-2026-9344)
slug: 2026-05-edimax-buffer-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-9344) exists in Edimax EW-7438RPn devices up to version 1.31, allowing remote attackers to execute arbitrary code by manipulating the pinCode/wlan-url argument in the /goform/formWpsStart file.
date: "2026-05-26T13:43:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - buffer_overflow
  - edimax
  - iot
  - webs
vendors:
  - Edimax
products:
  - EW-7438RPn (<= 1.31)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-9344
    cvss: 8.8
    epss: 0.00041
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9344
  - https://github.com/wudipjq/my_vuln/blob/main/Edimax/vuln_2/2.md
  - https://vuldb.com/submit/813885
  - https://vuldb.com/vuln/365307
  - https://vuldb.com/vuln/365307/cti
rules:
  - title: Detect CVE-2026-9344 Exploitation Attempt via Long URI
    description: Detects CVE-2026-9344 exploitation attempt based on abnormally long URI parameters to /goform/formWpsStart.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9344 Exploitation Attempt via POST Request
    description: Detects CVE-2026-9344 exploitation attempt via POST request to /goform/formWpsStart.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A stack-based buffer overflow vulnerability, identified as CVE-2026-9344, has been discovered in Edimax EW-7438RPn devices up to version 1.31. The vulnerability resides within the webs component, specifically in the `/goform/formWpsStart` file. By manipulating the `pinCode` or `wlan-url` arguments, a remote attacker can trigger a buffer overflow, potentially leading to arbitrary code execution. Public exploit code is available. The vendor, Edimax, has been contacted but has not provided a response or patch. This vulnerability poses a significant risk to users of affected Edimax devices, as it can be exploited remotely without authentication.

## Attack Chain

1.  The attacker identifies an Edimax EW-7438RPn device running a vulnerable firmware version (<= 1.31).
2.  The attacker sends a crafted HTTP request to the `/goform/formWpsStart` endpoint.
3.  The HTTP request includes a malicious payload in the `pinCode` or `wlan-url` parameter.
4.  The `webs` component processes the request without proper input validation.
5.  The oversized `pinCode` or `wlan-url` argument overwrites the stack buffer.
6.  The attacker injects malicious code into the overflowed buffer.
7.  The injected code is executed by the device, granting the attacker control.
8.  The attacker uses the compromised device as a foothold for further network attacks or data exfiltration.

## Impact

Successful exploitation of CVE-2026-9344 can lead to complete compromise of the Edimax EW-7438RPn device. An attacker could gain unauthorized access to the device's configuration, modify network settings, or use the device as a launching point for attacks against other devices on the network. Given the lack of vendor response, affected users are vulnerable until a patch or workaround is available.

## Recommendation

*   Apply the Sigma rule `Detect CVE-2026-9344 Exploitation Attempt via Long URI` to identify exploitation attempts based on abnormally long URI parameters in web server logs.
*   Apply the Sigma rule `Detect CVE-2026-9344 Exploitation Attempt via POST Request` to identify exploitation attempts based on POST requests to /goform/formWpsStart.
*   Monitor web server logs for requests to `/goform/formWpsStart` with unusually long `pinCode` or `wlan-url` parameters, as these could indicate exploitation attempts.
*   Consider deploying a web application firewall (WAF) rule to block requests with excessively long parameters to the vulnerable endpoint, mitigating the risk of buffer overflow.
