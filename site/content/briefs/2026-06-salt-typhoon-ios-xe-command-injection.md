---
brief_id: brief-2026-06-salt-typhoon-ios-xe-command-injection
event_id: brief-2026-06-salt-typhoon-ios-xe-command-injection
revision: 1
activity_at: "2026-06-14T19:38:52Z"
title: Salt Typhoon Cisco IOS XE Command Injection via Package Describe Shell Patterns
slug: 2026-06-salt-typhoon-ios-xe-command-injection
description: Salt Typhoon, an advanced persistent threat group, is leveraging command injection vulnerabilities in Cisco IOS XE devices, specifically using the 'request platform software package describe' command with malicious shell patterns to execute arbitrary commands, leading to potential network compromise and data exfiltration.
date: "2026-06-14T19:38:52Z"
lastmod: "2026-11-19T18:12:21Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Salt Typhoon
  - GhostEmperor
  - FamousSparrow
  - UNC5807
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2023-10-16T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.1.1:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.1.2:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.1.3:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.2.1:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.2.2:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.3.10:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.3.11:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.3.1a:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.3.2:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.3.3:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.3.4:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.3.5:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.3.5b:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.3.6:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.3.7:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.3.8:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.3.9:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.4.1:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.4.2:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:16.4.3:*:*:*:*:*:*:*
  - cpe:2.3:o:rockwellautomation:allen-bradley_stratix_5200_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:rockwellautomation:allen-bradley_stratix_5800_firmware:*:*:*:*:*:*:*:*
tags:
  - network
  - command_injection
  - cisco_ios_xe
  - threat_group
vendors:
  - Cisco
products:
  - Cisco IOS XE
affected_os:
  - Cisco IOS XE
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
cves:
  - id: CVE-2023-20198
    cvss: 10
    epss: 0.94013
    kev: true
    kev_status: "true"
  - id: CVE-2023-20273
    cvss: 7.2
    epss: 0.92615
    kev: true
    kev_status: "true"
references:
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a
  - https://blog.talosintelligence.com/salt-typhoon-analysis/
rules:
  - title: Detects Cisco IOS XE Command Injection Shell Patterns
    description: Detects attempts by the Salt Typhoon threat actor to execute arbitrary commands on Cisco IOS XE devices by leveraging command injection within the 'request platform software package describe' command using specific shell-style filename patterns.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1059.004
      - T1190
    data_sources:
      - network
      - cisco_ios_xe
rules_count: 1
updates:
  - at: "2026-11-19T18:12:21Z"
    level: L3
    summary: exploited:true; KEV CVE-2023-20198; KEV CVE-2023-20273
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

The threat actor known as Salt Typhoon is exploiting Cisco IOS XE devices, utilizing command injection techniques to execute arbitrary commands. This activity is specifically detected by identifying the `request platform software package describe` command when it includes suspicious shell-style filename patterns, such as `$(bash)n` or `/(bash)n`. This tradecraft, detailed in CISA and Talos advisories, indicates an attacker has likely gained initial access through the exploitation of a public-facing vulnerability (e.g., CVE-2023-20198 or CVE-2023-20273) and is attempting to gain further control or enumerate the compromised network device. The presence of these patterns is a strong indicator of malicious activity and warrants immediate investigation, as it signifies a critical compromise of network infrastructure.

## Attack Chain

1.  **Initial Access**: Salt Typhoon exploits a public-facing vulnerability in the Cisco IOS XE web UI or other exposed service (e.g., CVE-2023-20198 or CVE-2023-20273) to gain initial access to the device.
2.  **Command Injection**: The attacker leverages the vulnerability to inject commands into administrative functions, such as those related to software package description.
3.  **Command Execution Attempt**: The attacker executes the `request platform software package describe` command, embedding shell-style patterns like `$(bash)n` or `/(bash)n` within the `--filename` parameter to test command injection capabilities.
4.  **System Information Gathering / Payload Delivery**: If successful, the injected commands allow the attacker to execute arbitrary shell commands on the underlying Linux shell of the IOS XE device, potentially for system reconnaissance or to download further malicious payloads.
5.  **Persistence Establishment**: The attacker may establish persistent access by creating new user accounts, installing backdoors, or modifying system configurations.
6.  **Network Pivoting / Lateral Movement**: The compromised Cisco IOS XE device is then used as a pivot point to gain access to internal network segments or other sensitive resources.
7.  **Data Exfiltration / Network Disruption**: The final objective typically involves exfiltrating sensitive data, disrupting network operations, or maintaining long-term access for espionage.

## Impact

Successful exploitation by Salt Typhoon results in complete compromise of Cisco IOS XE network devices. This can lead to unauthorized access to the device's configuration and control plane, enabling the attacker to manipulate network traffic, bypass security controls, and establish a foothold within the organizational network. Victims could face severe consequences, including network outages, data breaches, and the use of the compromised infrastructure for further attacks. Specific victim numbers are not publicly detailed for this exact technique, but the related vulnerabilities (CVE-2023-20198, CVE-2023-20273) have seen widespread exploitation impacting various sectors globally.

## Recommendation

*   Deploy the Sigma rule `Detects Cisco IOS XE Command Injection Shell Patterns` in this brief to your SIEM and tune for your environment.
*   Ensure Cisco IOS-XE syslog with `sourcetype "cisco:ios"` is being ingested into your SIEM, as this is the log source for the detection rule.
*   Enable AAA command accounting or EEM catchall command logging on Cisco IOS XE devices to ensure `message_text` visibility.
*   Review network device configurations for any unusual users, files, or running processes on compromised Cisco IOS XE devices.
*   Refer to the CISA advisory (AA25-239A) and Talos blog (salt-typhoon-analysis) for comprehensive mitigation strategies related to Salt Typhoon activities.
