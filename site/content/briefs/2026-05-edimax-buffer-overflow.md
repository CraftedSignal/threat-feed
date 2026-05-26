---
title: Edimax BR-6675nD Buffer Overflow Vulnerability (CVE-2026-9380)
slug: 2026-05-edimax-buffer-overflow
description: A buffer overflow vulnerability (CVE-2026-9380) exists in Edimax BR-6675nD version 1.12, allowing a remote attacker to execute arbitrary code by manipulating the L2TPUserName argument in the formL2TPSetup function.
date: "2026-05-26T13:47:53Z"
type: advisory
types:
  - advisory
severities:
  - high
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
  - id: CVE-2026-9380
    cvss: 8.8
    epss: 0.00041
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9380
  - https://lavender-bicycle-a5a.notion.site/EDIMAX-BR-6675nD-formL2TPSetup-34b53a41781f805abdfbdcbe930ad70a?source=copy_link
  - https://vuldb.com/submit/811558
  - https://vuldb.com/vuln/365343
  - https://vuldb.com/vuln/365343/cti
rules:
  - title: Detect CVE-2026-9380 Exploitation Attempt — Long L2TPUserName
    description: Detects CVE-2026-9380 exploitation attempt — an HTTP POST request to /goform/formL2TPSetup with a very long L2TPUserName parameter, indicating a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9380 Exploitation Attempt — Abnormal HTTP Status Code
    description: Detects CVE-2026-9380 exploitation attempt — an HTTP POST request to /goform/formL2TPSetup resulting in a server error (5xx status code) after a request with long L2TPUserName, suggesting a buffer overflow caused a crash.
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

A buffer overflow vulnerability, identified as CVE-2026-9380, affects Edimax BR-6675nD router version 1.12. The vulnerability resides within the `formL2TPSetup` function located in the `/goform/formL2TPSetup` file, part of the POST Request Handler component. An attacker can exploit this flaw by crafting a malicious POST request with an overly long `L2TPUserName` argument. This leads to a buffer overflow, potentially allowing the attacker to execute arbitrary code on the device. The vulnerability can be exploited remotely and a proof-of-concept exploit has been publicly disclosed. The vendor was notified, but has not responded.

## Attack Chain

1.  The attacker identifies an Edimax BR-6675nD router running firmware version 1.12.
2.  The attacker crafts a malicious HTTP POST request targeting the `/goform/formL2TPSetup` endpoint.
3.  The POST request includes the `L2TPUserName` parameter with a value exceeding the expected buffer size.
4.  The router's web server processes the POST request and passes the `L2TPUserName` value to the `formL2TPSetup` function.
5.  The `formL2TPSetup` function copies the overly long `L2TPUserName` value into a fixed-size buffer without proper bounds checking.
6.  This buffer overflow overwrites adjacent memory regions, potentially including function return addresses or other critical data.
7.  The attacker gains the ability to execute arbitrary code on the device by controlling the overwritten return address.
8.  Successful exploitation leads to full control of the device, allowing the attacker to potentially eavesdrop on network traffic, modify router settings, or use the device as a botnet node.

## Impact

Successful exploitation of CVE-2026-9380 allows a remote attacker to gain complete control of the affected Edimax BR-6675nD router. This could lead to sensitive information disclosure, modification of router configurations, or the use of the compromised device in distributed denial-of-service (DDoS) attacks. Given the widespread use of such routers, a large number of devices are potentially vulnerable if unpatched.

## Recommendation

*   Deploy the Sigma rule `Detect CVE-2026-9380 Exploitation Attempt — Long L2TPUserName` to detect attempts to exploit this vulnerability in web server logs.
*   Inspect web server logs for POST requests to `/goform/formL2TPSetup` with unusually long `L2TPUserName` values, as detected by the Sigma rule.
*   Apply available firmware updates from Edimax to patch CVE-2026-9380.
