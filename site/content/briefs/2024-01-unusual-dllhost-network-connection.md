---
title: Unusual Network Connection via DllHost
slug: 2024-01-unusual-dllhost-network-connection
description: The rule identifies unusual instances of dllhost.exe making outbound network connections to non-local IPs, which may indicate adversarial Command and Control activity and defense evasion.
date: "2024-01-03T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - command-and-control
  - windows
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
products:
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/
  - https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/
  - https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
rules:
  - title: Unusual Network Connection via DllHost
    description: Detects unusual network connections initiated by dllhost.exe, excluding connections to private IP ranges.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - defense_evasion
    techniques:
      - T1071
      - T1218
    data_sources:
      - network_connection
      - windows
  - title: DllHost Process Started with Single Argument
    description: Detects dllhost.exe started with a single argument, which is considered unusual and potentially malicious.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The detection rule identifies unusual instances of dllhost.exe making outbound network connections, which may indicate adversarial command and control activity. Dllhost.exe is a legitimate Windows process used to host DLL services. Adversaries may exploit it for stealthy command and control by initiating unauthorized network connections to non-local IPs. This approach helps in identifying potential threats by focusing on unusual network behaviors associated with this process. The rule aims to detect activity related to defense evasion, where adversaries use system binaries to proxy execution. The detection logic relies on identifying dllhost.exe processes initiating network connections to destinations outside of commonly used private IP ranges.

## Attack Chain

1.  An attacker gains initial access to a Windows system (e.g., via phishing or exploitation).
2.  The attacker executes a malicious DLL file on the compromised system.
3.  The attacker uses dllhost.exe to host and execute the malicious DLL.
4.  The malicious DLL initiates a network connection to an external IP address, bypassing traditional process-based network monitoring.
5.  The attacker establishes a command and control (C2) channel via the dllhost.exe process.
6.  The attacker uses the C2 channel to send commands and receive data from the compromised system.
7.  The attacker performs lateral movement within the network.
8.  The attacker exfiltrates sensitive data from the compromised network.

## Impact

A successful attack can lead to the establishment of a covert command and control channel, allowing attackers to remotely control the compromised system. This can result in data theft, further compromise of the network, and potential financial loss. The references point to APT29 activity, suggesting sophisticated actors may leverage this technique.

## Recommendation

*   Enable Sysmon process creation (Event ID 1) and network connection (Event ID 3) logging to enhance visibility of process execution and network activity ([https://ela.st/sysmon-event-1-setup](https://ela.st/sysmon-event-1-setup), [https://ela.st/sysmon-event-3-setup](https://ela.st/sysmon-event-3-setup)).
*   Deploy the Sigma rule `Unusual Network Connection via DllHost` to your SIEM to detect suspicious outbound connections from dllhost.exe.
*   Investigate and whitelist legitimate software updates or enterprise applications that use dllhost.exe for network communications to reduce false positives, as described in the rule's analysis notes.
