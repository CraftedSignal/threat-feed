---
title: Tenda F451 Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-stack-overflow
description: A stack-based buffer overflow vulnerability in Tenda F451 version 1.0.0.7 allows remote attackers to execute arbitrary code by manipulating the 'page/menufacturer' argument in the fromSafeMacFilter function.
date: "2026-04-12T09:16:18Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2026-6124
  - buffer-overflow
  - router
  - tenda
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6124
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6124
  - https://github.com/Jimi-Lab/cve/issues/16
  - https://vuldb.com/vuln/356987
rules:
  - title: Detect Tenda F451 Stack Overflow Attempt via URI
    description: Detects attempts to exploit the Tenda F451 stack-based buffer overflow vulnerability (CVE-2026-6124) by monitoring for abnormally long 'page' or 'menufacturer' parameters in requests to '/goform/SafeMacFilter'.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect CVE-2026-6124 Exploitation attempt
    description: Detects requests to the affected /goform/SafeMacFilter endpoint
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

A stack-based buffer overflow vulnerability has been identified in Tenda F451 version 1.0.0.7. This flaw resides in the `fromSafeMacFilter` function of the `/goform/SafeMacFilter` file within the `httpd` component. Successful exploitation allows a remote attacker to execute arbitrary code on the affected device. The vulnerability is triggered by manipulating the `page/menufacturer` argument. Publicly available exploits exist, increasing the risk of widespread exploitation. Routers are often exposed to the internet, making them attractive targets for attackers looking to gain unauthorized access to networks.

## Attack Chain

1. Attacker sends a crafted HTTP GET request to the `/goform/SafeMacFilter` endpoint of the Tenda F451 router.
2. The request includes a malicious payload within the `page/menufacturer` argument.
3. The `httpd` component receives the request and passes the `page/menufacturer` argument to the `fromSafeMacFilter` function.
4. The `fromSafeMacFilter` function does not properly validate the length of the `page/menufacturer` argument.
5. Due to the missing validation, the supplied payload overflows the stack buffer.
6. The overflow overwrites critical data on the stack, including the return address.
7. Upon function return, control is transferred to the attacker's payload.
8. The attacker's payload executes with elevated privileges, allowing for complete control of the device.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the Tenda F451 router. This can lead to a variety of malicious outcomes, including complete device compromise, denial of service, and potential network intrusion. Given that this exploit is publicly available, a large number of unpatched Tenda F451 routers are at risk. Attackers could leverage compromised devices for botnet activities, data exfiltration, or lateral movement within a network.

## Recommendation

*   Apply available patches or firmware updates for Tenda F451 routers to remediate CVE-2026-6124.
*   Monitor web server logs (category: webserver, product: linux) for suspicious requests to `/goform/SafeMacFilter` containing unusually long `page` or `menufacturer` parameters, as detected by the provided Sigma rule.
*   Implement network intrusion detection systems (IDS) and intrusion prevention systems (IPS) rules to detect and block exploitation attempts targeting CVE-2026-6124.
