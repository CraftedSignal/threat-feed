---
title: Tenda AC5 Router Stack-Based Buffer Overflow (CVE-2026-4904)
slug: 2024-01-tenda-ac5-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-4904) exists in the Tenda AC5 router version 15.03.06.47, allowing remote attackers to execute arbitrary code by manipulating the 'funcpara1' argument in the '/goform/setcfm' endpoint.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-4904
  - buffer-overflow
  - tenda
  - router
  - webserver
vendors:
  - Tenda
products:
  - Tenda AC5 router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4904
rules:
  - title: Detect Tenda AC5 Buffer Overflow Attempt
    description: Detects attempts to exploit the CVE-2026-4904 stack-based buffer overflow vulnerability in Tenda AC5 routers by monitoring for abnormally long funcpara1 parameters in POST requests to /goform/setcfm, indicating a potential overflow attempt.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda AC5 Configuration Manipulation
    description: Detects POST requests to /goform/setcfm which might indicate configuration changes or exploitation attempts on Tenda AC5 routers.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical stack-based buffer overflow vulnerability, identified as CVE-2026-4904, has been discovered in Tenda AC5 router firmware version 15.03.06.47. The vulnerability resides in the `formSetCfm` function within the `/goform/setcfm` endpoint, specifically affecting the POST request handler. This flaw allows a remote, unauthenticated attacker to potentially execute arbitrary code on the device by sending a crafted POST request with a malicious value for the `funcpara1` argument. Given the ease of exploitation and the potential for complete system compromise, this vulnerability poses a significant risk to affected devices. Public disclosure of the exploit code increases the likelihood of widespread exploitation.

## Attack Chain

1.  The attacker identifies a vulnerable Tenda AC5 router running firmware version 15.03.06.47.
2.  The attacker crafts a malicious HTTP POST request targeting the `/goform/setcfm` endpoint.
3.  Within the POST request, the attacker includes the `funcpara1` argument with a string exceeding the expected buffer size.
4.  The Tenda AC5 router receives the crafted POST request and passes the `funcpara1` argument to the `formSetCfm` function.
5.  Due to insufficient bounds checking, the oversized `funcpara1` string overflows the allocated buffer on the stack.
6.  The buffer overflow overwrites adjacent memory on the stack, including the return address.
7.  The attacker carefully crafts the overflow to overwrite the return address with an address pointing to malicious code or a return-oriented programming (ROP) chain.
8.  When the `formSetCfm` function returns, execution jumps to the attacker-controlled address, resulting in arbitrary code execution on the router.

## Impact

Successful exploitation of CVE-2026-4904 grants the attacker complete control over the Tenda AC5 router. This can lead to a variety of malicious activities, including but not limited to: complete device takeover, denial of service, network traffic interception, DNS hijacking, and the installation of persistent backdoors. Given the widespread use of Tenda routers in homes and small businesses, a large number of devices are potentially vulnerable.

## Recommendation

*   Deploy the Sigma rule `Detect Tenda AC5 Buffer Overflow Attempt` to identify exploitation attempts against the vulnerable `/goform/setcfm` endpoint.
*   Apply any available patches or firmware updates released by Tenda to address CVE-2026-4904.
*   Monitor web server logs for suspicious POST requests targeting the `/goform/setcfm` endpoint with unusually long `funcpara1` parameters (see IOC context in the rule description).
