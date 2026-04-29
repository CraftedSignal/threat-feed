---
title: Tenda F456 Router Buffer Overflow Vulnerability
slug: 2026-04-tenda-buffer-overflow
description: A buffer overflow vulnerability in Tenda F456 router version 1.0.0.5 allows a remote attacker to execute arbitrary code by exploiting the fromSafeClientFilter function in the /goform/SafeClientFilter endpoint through manipulation of the 'menufacturer/Go' argument.
date: "2026-04-26T11:16:06Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - buffer-overflow
  - remote-code-execution
  - cve-2026-7033
  - router
vendors:
  - Tenda
products:
  - F456 1.0.0.5
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-7033
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7033
  - https://github.com/Litengzheng/vuldb_new/blob/main/F456/vul_123/README.md
  - https://vuldb.com/vuln/359613
rules:
  - title: Detect Tenda F456 Buffer Overflow Attempt via URI
    description: Detects potential buffer overflow attempts on Tenda F456 routers by monitoring HTTP requests to the /goform/SafeClientFilter endpoint with excessively long menufacturer/Go parameters.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda F456 POST to vulnerable endpoint
    description: Detects POST requests to the /goform/SafeClientFilter endpoint on Tenda devices, which is associated with CVE-2026-7033.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A buffer overflow vulnerability has been identified in Tenda F456 router, specifically version 1.0.0.5. The vulnerability resides within the `fromSafeClientFilter` function located in the `/goform/SafeClientFilter` file. Successful exploitation allows a remote attacker to inject and execute arbitrary code. Publicly available exploit code exists, increasing the risk of widespread exploitation targeting vulnerable Tenda F456 devices. This issue poses a significant threat to network security, as a compromised router can lead to data breaches, denial of service, or further network intrusion.

## Attack Chain

1.  The attacker identifies a Tenda F456 router running firmware version 1.0.0.5 exposed to the internet.
2.  The attacker crafts a malicious HTTP POST request targeting the `/goform/SafeClientFilter` endpoint.
3.  The crafted request includes a specially designed payload within the `menufacturer/Go` argument. This payload is designed to trigger a buffer overflow in the `fromSafeClientFilter` function.
4.  The `fromSafeClientFilter` function processes the malicious input without proper bounds checking.
5.  The oversized payload overwrites adjacent memory regions, potentially including return addresses or other critical data.
6.  When the `fromSafeClientFilter` function attempts to return, the overwritten return address is used, redirecting execution flow to attacker-controlled memory.
7.  The attacker-controlled memory contains shellcode or other malicious instructions.
8.  The router executes the attacker's code, granting the attacker control over the device.

## Impact

Successful exploitation of this vulnerability can result in complete compromise of the Tenda F456 router. An attacker can gain unauthorized access to network traffic, modify router settings, or use the compromised device as a launchpad for further attacks within the network. Given the public availability of exploit code, a large number of Tenda F456 routers could be targeted, potentially affecting numerous home and small business networks. A successful attack could lead to data theft, service disruption, and reputational damage.

## Recommendation

*   Apply any available patches or firmware updates released by Tenda to address CVE-2026-7033 on the F456 1.0.0.5 routers.
*   Implement network intrusion detection systems (IDS) or intrusion prevention systems (IPS) rules to detect and block malicious requests targeting the `/goform/SafeClientFilter` endpoint.
*   Deploy the Sigma rules provided below to your SIEM to detect exploitation attempts targeting the vulnerable endpoint.
*   Monitor web server logs for suspicious POST requests to `/goform/SafeClientFilter` with abnormally large `menufacturer/Go` argument values.
