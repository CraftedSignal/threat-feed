---
title: Belkin F9K1122 Router Stack-Based Buffer Overflow
slug: 2026-03-belkin-rce
description: A stack-based buffer overflow vulnerability exists in Belkin F9K1122 version 1.00.33, allowing remote attackers to execute arbitrary code by manipulating the 'webpage' argument in the 'formWISP5G' function.
date: "2026-03-23T03:16:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2026-4566
  - buffer-overflow
  - router
  - rce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4566
  - https://github.com/Litengzheng/vul_db/blob/main/Belkin/vul_151/README.md
rules:
  - title: Belkin Router RCE Attempt
    description: Detects attempts to exploit the stack-based buffer overflow in Belkin F9K1122 routers via a long webpage parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Belkin F9K1122 Router User Agent
    description: Detects connections using the Belkin F9K1122 Router's default User Agent string.
    platform: sigma
    severity: informational
    tactics:
      - reconnaissance
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stack-based buffer overflow vulnerability has been discovered in the Belkin F9K1122 router, specifically version 1.00.33. The vulnerability resides within the `formWISP5G` function located in the `/goform/formWISP5G` file. Successful exploitation involves manipulating the `webpage` argument, leading to arbitrary code execution. This vulnerability is remotely exploitable, making it a significant threat. Publicly available exploit code exists, increasing the likelihood of exploitation. The vendor was notified but has not responded, indicating a lack of timely patching. This poses a high risk to users of the affected Belkin router model.

## Attack Chain

1.  Attacker identifies a vulnerable Belkin F9K1122 router running firmware version 1.00.33.
2.  The attacker crafts a malicious HTTP request targeting the `/goform/formWISP5G` endpoint.
3.  Within the HTTP request, the `webpage` argument is manipulated to contain a payload exceeding the buffer size.
4.  The router's web server processes the request and passes the attacker-controlled input to the `formWISP5G` function.
5.  The `formWISP5G` function attempts to copy the oversized `webpage` argument into a fixed-size buffer on the stack.
6.  A stack-based buffer overflow occurs, overwriting adjacent memory regions, including the return address.
7.  The attacker gains control of the program execution flow by redirecting it to attacker-controlled code.
8.  The attacker executes arbitrary code on the router, potentially gaining complete control of the device.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary code on the Belkin F9K1122 router. This can lead to a complete compromise of the device, allowing the attacker to modify router settings, intercept network traffic, or use the router as a pivot point for further attacks within the network. Given the wide use of these routers in home and small business environments, a successful widespread attack could impact thousands of users. The absence of a vendor patch exacerbates the risk.

## Recommendation

*   Implement a web application firewall (WAF) rule to detect and block requests with excessively long `webpage` arguments to the `/goform/formWISP5G` endpoint, mitigating exploitation attempts (Attack Chain step 3).
*   Deploy the Sigma rule provided to detect suspicious web requests targeting the vulnerable endpoint (see "Belkin Router RCE Attempt" rule).
*   Monitor web server logs for unusual activity related to the `/goform/formWISP5G` endpoint (Attack Chain step 4).
