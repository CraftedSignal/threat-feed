---
title: Tenda F456 Stack-Based Buffer Overflow Vulnerability (CVE-2026-6200)
slug: 2026-04-tenda-overflow
description: A stack-based buffer overflow vulnerability in the formwebtypelibrary function of Tenda F456 router version 1.0.0.5 allows a remote attacker to execute arbitrary code by manipulating the menufacturer/Go argument in a request to /goform/webtypelibrary.
date: "2026-04-13T19:16:58Z"
severities:
  - critical
tags:
  - cve-2026-6200
  - tenda
  - router
  - buffer-overflow
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-6200
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6200
  - https://github.com/Litengzheng/vuldb_new/blob/main/F456/vul_117/README.md
  - https://vuldb.com/vuln/357122
rules:
  - title: Detect Tenda F456 Webtype Library Buffer Overflow Attempt
    description: Detects potential attempts to exploit the CVE-2026-6200 vulnerability by identifying HTTP POST requests to the /goform/webtypelibrary endpoint with excessively long 'menufacturer/Go' parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Tenda Router Web Interface Access
    description: Detects access to the Tenda router web interface, which may indicate reconnaissance activity.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical stack-based buffer overflow vulnerability, tracked as CVE-2026-6200, affects Tenda F456 routers running firmware version 1.0.0.5. The vulnerability resides within the `formwebtypelibrary` function located in the `/goform/webtypelibrary` file. An attacker can exploit this flaw by crafting a malicious request that manipulates the `menufacturer/Go` argument, leading to a buffer overflow. The vulnerability is remotely exploitable, meaning an attacker does not need local access to the device. Public exploits are available, increasing the likelihood of widespread exploitation. Successful exploitation could allow an attacker to execute arbitrary code on the router, potentially leading to complete device compromise, network access, or denial of service.

## Attack Chain

1.  The attacker identifies a vulnerable Tenda F456 router running firmware version 1.0.0.5.
2.  The attacker crafts a malicious HTTP POST request targeting the `/goform/webtypelibrary` endpoint.
3.  Within the POST request, the attacker includes the `menufacturer/Go` argument with a value exceeding the buffer's allocated size.
4.  The router's `formwebtypelibrary` function processes the request without proper bounds checking on the `menufacturer/Go` argument.
5.  The excessive data written to the buffer overwrites adjacent memory locations on the stack.
6.  The attacker carefully crafts the overflow data to overwrite the return address with the address of malicious code.
7.  When the `formwebtypelibrary` function returns, it jumps to the attacker's code, granting arbitrary code execution.
8.  The attacker can then use this code execution to install malware, modify router settings, or pivot to other devices on the network.

## Impact

Successful exploitation of CVE-2026-6200 allows attackers to gain complete control of the affected Tenda F456 router. This can lead to a variety of malicious activities, including eavesdropping on network traffic, injecting malicious code into websites visited by connected devices, or using the compromised router as a bot in a distributed denial-of-service (DDoS) attack. Given the availability of public exploits, a large number of Tenda F456 users are at risk, particularly those who have not applied security updates or enabled proper firewall protection. If exploited, entire home or small business networks are vulnerable.

## Recommendation

*   Deploy the Sigma rule `Detect Tenda F456 Webtype Library Buffer Overflow Attempt` to identify malicious requests targeting the vulnerable endpoint (logsource: webserver).
*   Inspect web server logs for POST requests to `/goform/webtypelibrary` with abnormally long `menufacturer/Go` argument values.
*   Implement rate limiting and input validation on the `/goform/webtypelibrary` endpoint to mitigate the risk of buffer overflows.
*   Contact Tenda support for available patches or firmware updates to address CVE-2026-6200.
