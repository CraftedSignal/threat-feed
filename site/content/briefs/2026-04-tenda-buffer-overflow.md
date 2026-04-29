---
title: Tenda F451 Router Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-buffer-overflow
description: A stack-based buffer overflow vulnerability exists in Tenda F451 version 1.0.0.7, allowing remote attackers to execute arbitrary code by manipulating the `mit_ssid` argument in the `/goform/AdvSetWrlsafeset` file.
date: "2026-04-09T23:17:02Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2026-5988
  - buffer-overflow
  - tenda
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5988
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5988
  - https://github.com/Jimi-Lab/cve/issues/4
  - https://vuldb.com/vuln/356542
rules:
  - title: Detect Suspicious AdvSetWrlsafeset Request
    description: Detects HTTP requests to /goform/AdvSetWrlsafeset with an unusually long mit_ssid parameter, indicative of a buffer overflow attempt.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Large POST Request to AdvSetWrlsafeset
    description: Detects abnormally large POST requests to the /goform/AdvSetWrlsafeset endpoint, potentially indicating a buffer overflow attack.
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

A stack-based buffer overflow vulnerability has been identified in Tenda F451 router version 1.0.0.7. The vulnerability resides within the `formWrlsafeset` function of the `/goform/AdvSetWrlsafeset` file. A remote attacker can exploit this flaw by crafting a malicious request with an overly long `mit_ssid` argument, leading to potential arbitrary code execution on the device. Public exploits for this vulnerability are available, making it imperative for users of affected Tenda devices to take immediate action. This vulnerability poses a significant risk, as successful exploitation could grant an attacker full control over the vulnerable device.

## Attack Chain

1.  The attacker identifies a Tenda F451 router running firmware version 1.0.0.7 exposed to the internet.
2.  The attacker crafts a malicious HTTP POST request targeting the `/goform/AdvSetWrlsafeset` endpoint.
3.  The crafted request includes the `mit_ssid` argument with a string exceeding the buffer's expected size.
4.  The router's web server processes the request and passes the `mit_ssid` argument to the `formWrlsafeset` function.
5.  Due to the insufficient bounds checking, the overly long `mit_ssid` value overflows the stack-based buffer.
6.  The buffer overflow overwrites critical data on the stack, including the return address.
7.  The attacker carefully crafts the overflowed data to redirect execution to a location containing malicious code.
8.  The malicious code executes with the privileges of the web server process, potentially granting the attacker full control of the device.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary code on the affected Tenda F451 router. This can lead to complete compromise of the device, allowing the attacker to modify router settings, intercept network traffic, or use the device as a botnet node. Given the widespread use of Tenda routers, this vulnerability has the potential to impact a large number of users and networks.

## Recommendation

*   Apply any available firmware updates released by Tenda to patch CVE-2026-5988.
*   Deploy the Sigma rule `Detect Suspicious AdvSetWrlsafeset Request` to detect exploitation attempts targeting the vulnerable endpoint.
*   Monitor web server logs for unusually long `mit_ssid` parameters in requests to `/goform/AdvSetWrlsafeset`.
