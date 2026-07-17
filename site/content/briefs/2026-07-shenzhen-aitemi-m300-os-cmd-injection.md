---
title: 'CVE-2026-58457: Shenzhen Aitemi M300 Wi-Fi Repeater Unauthenticated OS Command Injection'
slug: 2026-07-shenzhen-aitemi-m300-os-cmd-injection
description: An unauthenticated OS command injection vulnerability, CVE-2026-58457, exists in the Shenzhen Aitemi M300 Wi-Fi Repeater (hardware model MT02), allowing network-adjacent attackers to execute arbitrary shell commands and gain full root-level control by injecting unsanitized input into the `smacfilter_conf` handler's GET parameters within the `commuos` web backend.
date: "2026-07-01T20:26:19Z"
lastmod: "2026-07-17T00:01:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - network
  - command-injection
  - vulnerability
  - firmware
  - iot
vendors:
  - Shenzhen Aitemi
products:
  - M300 Wi-Fi Repeater (hardware model MT02)
  - M300 Wi-Fi Repeater
  - MT02
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: unauthenticated OS command injection vulnerability that allows network-adjacent attackers to execute arbitrary shell commands
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: execute arbitrary shell commands by injecting unsanitized input through the smacfilter_conf handler in the commuos web backend...granting full root-level control of the device.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58457
  - https://sploitus.com/exploit?id=5A474EE3-FF1F-594E-B4E1-2CAE4FE9D32A&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=5A474EE3-FF1F-594E-B4E1-2CAE4FE9D32A
  - type: url
    value: http://your-ip:8080/
  - type: url
    value: https://www.vulncheck.com/advisories/shenzhen-aitemi-m300-mt02-unauthenticated-os-command-injection-via-protocol-csp
  - type: url
    value: https://github.com/IEATASICS/m300-repeater-bugs
ioc_counts:
  url: 4
rules:
  - title: Detects CVE-2026-58457 Exploitation — Shenzhen Aitemi M300 Wi-Fi Repeater OS Command Injection
    description: Detects exploitation attempts of CVE-2026-58457 by monitoring HTTP GET requests to the /commuos/smacfilter_conf handler with OS command injection characters in 'name', 'enable', or 'mac' parameters.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.006
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-17T00:01:18Z"
    level: L1
    summary: OS linux
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=5A474EE3-FF1F-594E-B4E1-2CAE4FE9D32A&utm_source=rss&utm_medium=rss
---

The National Vulnerability Database (NVD) has disclosed CVE-2026-58457, an unauthenticated OS command injection vulnerability affecting the Shenzhen Aitemi M300 Wi-Fi Repeater (hardware model MT02). This critical flaw allows network-adjacent attackers to achieve full root-level control over the device. Attackers can leverage the `smacfilter_conf` handler in the `commuos` web backend by injecting unsanitized input into the 'name', 'enable', or 'mac' GET parameters. This vulnerability stems from the device's firmware improperly handling user-supplied data, passing it directly to `sprintf()` and then executing it via `doSystemCmdComlib()`, making these devices highly susceptible to compromise without authentication.

## Attack Chain

1.  Attacker identifies an internet-facing or network-adjacent Shenzhen Aitemi M300 Wi-Fi Repeater.
2.  Attacker crafts a malicious HTTP GET request targeting the `/commuos/smacfilter_conf` handler in the device's web backend.
3.  The request includes a payload appended with semicolon-delimited OS commands within the 'name', 'enable', or 'mac' GET parameters (e.g., `?name=test;id`).
4.  The vulnerable `commuos` web backend receives the request and processes the injected parameters without proper sanitization.
5.  The unsanitized input, including the attacker's OS command, is concatenated into a command string using `sprintf()`.
6.  The `doSystemCmdComlib()` function executes the malformed command string with root privileges on the device's underlying operating system.
7.  Attacker gains full root-level control over the Shenzhen Aitemi M300 Wi-Fi Repeater.
8.  Attacker can then perform actions such as installing backdoors, modifying network configurations, or launching further attacks from the compromised device.

## Impact

A successful exploitation of CVE-2026-58457 grants network-adjacent attackers unauthenticated, full root-level control over the Shenzhen Aitemi M300 Wi-Fi Repeater. This level of access allows attackers to completely compromise the device, potentially reconfiguring it for malicious purposes, intercepting network traffic, launching denial-of-service attacks, or establishing a foothold within the victim's network. Given the nature of Wi-Fi repeaters, compromised devices could become an entry point for lateral movement or data exfiltration from connected devices on the network, posing a significant risk to data confidentiality, integrity, and availability for home and small office networks.

## Recommendation

*   Apply the vendor-provided firmware update for Shenzhen Aitemi M300 Wi-Fi Repeater (hardware model MT02) that addresses CVE-2026-58457 immediately.
*   Deploy the `Detects CVE-2026-58457 Exploitation — Shenzhen Aitemi M300 Wi-Fi Repeater OS Command Injection` Sigma rule provided in this brief to your SIEM.
*   Ensure webserver access logs are enabled and forwarded to your SIEM for all internet-facing network devices to facilitate detection of exploitation attempts.
