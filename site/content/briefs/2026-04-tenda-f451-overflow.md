---
title: Tenda F451 Remote Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-f451-overflow
description: A remote stack-based buffer overflow vulnerability (CVE-2026-5991) exists in the Tenda F451 router version 1.0.0.7, allowing unauthenticated attackers to potentially execute arbitrary code via a crafted request to the `/goform/WrlExtraSet` endpoint.
date: "2026-04-10T00:16:36Z"
severities:
  - critical
tags:
  - cve-2026-5991
  - tenda
  - buffer-overflow
  - router
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5991
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5991
  - https://github.com/Jimi-Lab/cve/issues/9
  - https://vuldb.com/vuln/356545
rules:
  - title: Detect Tenda F451 Buffer Overflow Attempt
    description: Detects potential buffer overflow attempts against Tenda F451 routers by monitoring for abnormally long GO parameters in requests to the /goform/WrlExtraSet endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect High Volume of Requests to Tenda Configuration Page
    description: Detects a high volume of requests to /goform/WrlExtraSet, potentially indicating a brute-force or automated exploitation attempt targeting CVE-2026-5991.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stack-based buffer overflow vulnerability has been identified in Tenda F451 version 1.0.0.7. The vulnerability resides within the `formWrlExtraSet` function in the `/goform/WrlExtraSet` file. An attacker can trigger the overflow by manipulating the `GO` argument in a crafted HTTP request. This vulnerability is remotely exploitable and could allow an attacker to execute arbitrary code on the device. Publicly available exploits exist, increasing the risk of exploitation. Given the widespread use of these routers, this vulnerability presents a significant risk to home and small business networks.

## Attack Chain

1. An attacker identifies a vulnerable Tenda F451 router running firmware version 1.0.0.7.
2. The attacker crafts a malicious HTTP POST request targeting the `/goform/WrlExtraSet` endpoint.
3. The HTTP POST request includes the `GO` parameter with a string exceeding the buffer size allocated for it in the `formWrlExtraSet` function.
4. The router's web server receives the crafted HTTP POST request and passes the `GO` parameter to the `formWrlExtraSet` function without proper bounds checking.
5. The `formWrlExtraSet` function writes the oversized `GO` parameter into a stack-based buffer, causing a buffer overflow.
6. The overflow overwrites adjacent memory on the stack, including the return address.
7. The attacker controls the overwritten return address to point to malicious code injected into the request.
8. When the `formWrlExtraSet` function returns, it jumps to the attacker-controlled address, executing arbitrary code on the router.

## Impact

Successful exploitation of CVE-2026-5991 allows an unauthenticated remote attacker to execute arbitrary code on the Tenda F451 router. This could lead to complete compromise of the device, allowing the attacker to eavesdrop on network traffic, inject malicious content into web pages, or use the router as a launchpad for further attacks against other devices on the network or the internet. Given the number of potentially affected devices, this vulnerability presents a significant risk.

## Recommendation

*   Deploy the Sigma rule `Detect Tenda F451 Buffer Overflow Attempt` to identify potential exploitation attempts based on abnormally long GO parameter values in web requests (see "rules" section).
*   Monitor web server logs for requests to `/goform/WrlExtraSet` with unusually long `GO` parameter values, indicative of potential buffer overflow attempts.
*   Implement rate limiting on requests to `/goform/WrlExtraSet` to mitigate brute-force exploitation attempts.
*   Since the vendor patch is not available, consider replacing vulnerable Tenda F451 routers with more secure alternatives.
