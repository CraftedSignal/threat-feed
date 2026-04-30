---
title: Tenda 4G300 Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-stack-overflow
description: A remote stack-based buffer overflow vulnerability exists in the Tenda 4G300 router, version US_4G300V1.0Mt_V1.01.42_CN_TDC01, allowing an attacker to potentially execute arbitrary code by manipulating the 'page' argument to the sub_427C3C function in the /goform/SafeMacFilter file.
date: "2026-04-30T03:16:01Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - buffer-overflow
  - tenda
  - router
  - cve-2026-7470
vendors:
  - Tenda
products:
  - 4G300
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1213
    technique_name: Exploitation of Memory Corruption
cves:
  - id: CVE-2026-7470
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7470
  - https://github.com/Axelioc/CVE/blob/main/Tenda/US_4G300/sub_427C3C/sub_427C3C.md
  - https://vuldb.com/vuln/360206
rules:
  - title: Detect Tenda 4G300 Suspected Stack Buffer Overflow Attempt
    description: Detects potential stack buffer overflow attempts against Tenda 4G300 routers by monitoring for unusually long 'page' parameters in POST requests to the '/goform/SafeMacFilter' endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda 4G300 Vulnerable Firmware Version
    description: Detects web requests originating from or directed towards Tenda 4G300 routers running the vulnerable firmware version US_4G300V1.0Mt_V1.01.42_CN_TDC01 based on the User-Agent header.
    platform: sigma
    severity: informational
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stack-based buffer overflow vulnerability has been identified in Tenda 4G300 routers, specifically version US_4G300V1.0Mt_V1.01.42_CN_TDC01. The vulnerability resides within the `sub_427C3C` function located in the `/goform/SafeMacFilter` file. An attacker can exploit this flaw by manipulating the `page` argument in a crafted request, leading to a buffer overflow and potentially allowing for arbitrary code execution on the affected device. The vulnerability, identified as CVE-2026-7470, poses a significant risk as remote exploitation is possible, and a proof-of-concept exploit is publicly available, increasing the likelihood of malicious actors leveraging this vulnerability.

## Attack Chain

1. The attacker identifies a Tenda 4G300 router running the vulnerable firmware version US_4G300V1.0Mt_V1.01.42_CN_TDC01.
2. The attacker crafts a malicious HTTP POST request targeting the `/goform/SafeMacFilter` endpoint.
3. The crafted request includes the `page` argument with a payload exceeding the buffer size allocated for it within the `sub_427C3C` function.
4. The router processes the HTTP request, passing the oversized `page` argument to the vulnerable function.
5. The `sub_427C3C` function attempts to write the oversized data into a stack-based buffer, causing a buffer overflow.
6. The buffer overflow overwrites adjacent memory on the stack, including the return address.
7. The attacker redirects execution flow to a malicious code payload injected into the request or elsewhere in memory.
8. The injected code executes with the privileges of the router process, potentially allowing the attacker to gain full control of the device.

## Impact

Successful exploitation of this vulnerability can lead to complete compromise of the Tenda 4G300 router. An attacker could gain unauthorized access to the device's configuration, intercept network traffic, or use the router as a launching point for further attacks against other devices on the network or the internet. Given the widespread use of these routers in homes and small businesses, a successful attack could impact a large number of users.

## Recommendation

*   Monitor web server logs for unusual POST requests to `/goform/SafeMacFilter` with abnormally long `page` parameters. Use the provided Sigma rule to detect suspicious activity.
*   Implement rate limiting on the `/goform/SafeMacFilter` endpoint to mitigate potential brute-force exploitation attempts.
*   Apply any available patches or firmware updates released by Tenda to address CVE-2026-7470.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
