---
title: Totolink N300RH Stack-Based Buffer Overflow Vulnerability (CVE-2026-10187)
slug: 2026-05-totolink-rce
description: A stack-based buffer overflow vulnerability, CVE-2026-10187, exists in the setWiFiBasicConfig function of the wireless.so file in the Web Management Interface of Totolink N300RH version 6.1c.1353_B20190305, allowing a remote attacker to execute arbitrary code by manipulating the KeyStr argument.
date: "2026-05-31T15:18:40Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - stack-buffer-overflow
  - remote-code-execution
  - router
vendors:
  - Totolink
products:
  - N300RH 6.1c.1353_B20190305
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-10187
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10187
  - https://vuldb.com/cve/CVE-2026-10187
  - https://vuldb.com/submit/819971
  - https://vuldb.com/submit/820133
  - https://vuldb.com/vuln/367468
  - https://vuldb.com/vuln/367468/cti
  - https://www.totolink.net/
  - https://wx.mail.qq.com/s?k=iXbjuHnfMwoD0oWW3v
rules:
  - title: Detect CVE-2026-10187 Exploitation Attempt via Long KeyStr
    description: Detects CVE-2026-10187 exploitation attempt by monitoring for HTTP POST requests to setWiFiBasicConfig with excessively long KeyStr values, indicating a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-10187 Exploitation Attempt via setWiFiBasicConfig
    description: Detects CVE-2026-10187 exploitation attempt by monitoring HTTP POST requests to the web management interface specifically targeting the `setWiFiBasicConfig` function in the wireless settings.
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

A stack-based buffer overflow vulnerability has been identified in Totolink N300RH router, version 6.1c.1353_B20190305. The vulnerability resides in the `setWiFiBasicConfig` function within the `wireless.so` file, a component of the device's web management interface. Publicly available exploits demonstrate that a remote attacker can leverage this vulnerability by manipulating the `KeyStr` argument passed to the vulnerable function, resulting in arbitrary code execution on the device. The affected version was released in March 2019, suggesting that many devices are potentially vulnerable due to lack of updates. This poses a significant risk, as successful exploitation could allow attackers to gain full control of the router, compromise connected devices, and intercept network traffic.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink N300RH router running firmware version 6.1c.1353_B20190305.
2.  The attacker sends a crafted HTTP request to the router's web management interface.
3.  The HTTP request targets the `setWiFiBasicConfig` function.
4.  The request includes a malicious payload in the `KeyStr` argument, designed to overflow the stack buffer.
5.  The `wireless.so` library processes the request without proper bounds checking on the `KeyStr` argument.
6.  The buffer overflow overwrites critical memory regions, including the return address.
7.  Upon returning from the function, execution jumps to the attacker-controlled address, allowing for arbitrary code execution.
8.  The attacker gains a shell on the router and can perform malicious actions.

## Impact

Successful exploitation of CVE-2026-10187 can lead to full compromise of the Totolink N300RH router. Attackers can leverage this access to intercept network traffic, modify DNS settings, create backdoors, and potentially compromise other devices on the network. Due to the high CVSS score (9.8), the impact is considered critical, allowing for complete control over the affected device. Given the nature of routers as network gateways, this vulnerability can serve as an entry point for wider attacks on home or small business networks.

## Recommendation

*   Deploy the Sigma rule `Detect CVE-2026-10187 Exploitation Attempt via Long KeyStr` to identify suspicious HTTP requests targeting the `setWiFiBasicConfig` function with abnormally long `KeyStr` arguments.
*   Block or investigate any traffic to the `setWiFiBasicConfig` endpoint originating from unexpected IP addresses, based on observed network connections.
*   Monitor webserver logs for POST requests to the `setWiFiBasicConfig` endpoint, based on webserver log source.
