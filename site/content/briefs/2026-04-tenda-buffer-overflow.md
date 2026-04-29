---
title: Tenda F456 Router Buffer Overflow Vulnerability (CVE-2026-7097)
slug: 2026-04-tenda-buffer-overflow
description: A buffer overflow vulnerability exists in Tenda F456 version 1.0.0.5 within the fromwebExcptypemanFilter function of the /goform/webExcptypemanFilter component's httpd server, which can be triggered remotely by manipulating the page argument leading to potential remote code execution.
date: "2026-04-27T08:16:02Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - buffer-overflow
  - router
  - remote-code-execution
  - cve
vendors:
  - Tenda
products:
  - F456
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7097
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7097
rules:
  - title: Detect Tenda F456 Buffer Overflow Attempt via URI Length
    description: Detects potential buffer overflow attempts on Tenda F456 routers by monitoring for abnormally long URI queries targeting the vulnerable endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda F456 Buffer Overflow Attempt via Suspicious Characters
    description: Detects potential buffer overflow attempts by looking for suspicious character sequences within the URI query to the vulnerable endpoint.
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

A buffer overflow vulnerability, identified as CVE-2026-7097, has been discovered in Tenda F456 router version 1.0.0.5. The vulnerability resides in the `fromwebExcptypemanFilter` function within the `/goform/webExcptypemanFilter` component of the device's `httpd` server. Successful exploitation of this vulnerability allows a remote attacker to cause a buffer overflow by manipulating the `page` argument, potentially leading to arbitrary code execution on the affected device. Given the public availability of exploit code, this vulnerability poses a significant risk to users of the Tenda F456 router.

## Attack Chain

1.  The attacker identifies a Tenda F456 router with firmware version 1.0.0.5 exposed to the internet.
2.  The attacker crafts a malicious HTTP request targeting the `/goform/webExcptypemanFilter` endpoint.
3.  The attacker includes a specially crafted `page` argument within the HTTP request, designed to overflow the buffer in the `fromwebExcptypemanFilter` function.
4.  The `httpd` server processes the request and calls the vulnerable function.
5.  The `fromwebExcptypemanFilter` function copies the attacker-controlled `page` argument into a fixed-size buffer without proper bounds checking.
6.  The buffer overflow corrupts adjacent memory regions, potentially overwriting critical data or code pointers.
7.  The attacker redirects program execution to attacker-controlled code by overwriting a return address.
8.  The attacker achieves remote code execution on the Tenda F456 router, potentially gaining full control of the device.

## Impact

Successful exploitation of CVE-2026-7097 can lead to complete compromise of the Tenda F456 router. This allows attackers to execute arbitrary code, potentially enabling them to modify device settings, intercept network traffic, or use the compromised device as part of a botnet. Given the ease of exploitation with publicly available exploits, a widespread attack targeting vulnerable Tenda routers is possible.

## Recommendation

*   Monitor web server logs for requests to `/goform/webExcptypemanFilter` with unusually long `page` parameters using the provided Sigma rule.
*   Implement rate limiting on HTTP requests to the `/goform/webExcptypemanFilter` endpoint to mitigate potential exploitation attempts.
*   Consider deploying a web application firewall (WAF) rule to filter out malicious requests targeting CVE-2026-7097 based on the payload structure.
