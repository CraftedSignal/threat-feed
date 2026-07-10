---
title: Suspicious DNS Queries to Telegram Bot API
slug: 2024-01-telegram-bot-dns-query
description: Detection of DNS queries to api.telegram.org by processes other than telegram.exe indicates potential command and control communication via Telegram bots, a technique leveraged by malware to establish covert communication channels.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - telegram
  - bot
  - c2
  - command-and-control
  - dns
vendors:
  - Telegram
products:
  - Telegram Bot API
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
references:
  - https://www.splunk.com/en_us/blog/security/threat-advisory-telegram-crypto-botnet-strt-ta01.html
iocs:
  - type: domain
    value: api.telegram.org
ioc_counts:
  domain: 1
rules:
  - title: Detect Suspicious Telegram DNS Queries
    description: Detects DNS queries to api.telegram.org from processes other than the legitimate Telegram application, which can indicate command and control activity.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.004
      - T1102.002
    data_sources:
      - dns_query
      - windows
  - title: Detect Suspicious Telegram Network Connections
    description: Detects network connections to Telegram's infrastructure from unusual processes.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.004
      - T1102.002
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This threat brief addresses the use of Telegram bots by malicious actors for command and control (C2) communications. Threat actors leverage Telegram's API to establish covert channels with compromised systems, enabling them to issue commands and exfiltrate data discreetly. The detection focuses on identifying DNS queries to `api.telegram.org` originating from processes other than the legitimate `telegram.exe`, which is indicative of unauthorized use of the Telegram API. This technique allows attackers to bypass traditional security measures by utilizing a popular and trusted platform for malicious purposes. Identifying and blocking this activity is crucial to preventing data theft and further compromise. This activity has been observed in malware families like Crypto Stealer, 0bj3ctivity Stealer, and BlankGrabber Stealer.

## Attack Chain

1.  A user unknowingly executes a malicious file (e.g., via phishing or drive-by download).
2.  The malicious file executes a process (e.g., a script interpreter like `powershell.exe` or `python.exe`).
3.  This process makes a DNS query to resolve `api.telegram.org` to obtain the IP address of the Telegram Bot API server.
4.  The malicious process establishes a network connection to the resolved IP address on port 443 (HTTPS) to communicate with the Telegram bot.
5.  The compromised system sends information (system data, credentials, files) to the attacker-controlled Telegram bot.
6.  The attacker sends commands to the bot, which relays these commands to the compromised system for execution.
7.  The malicious process executes commands received from the Telegram bot.
8.  The attacker achieves their objective (e.g., data theft, credential harvesting, lateral movement).

## Impact

Successful exploitation can lead to data exfiltration, system compromise, and further propagation of malware within the network. If a compromised system successfully communicates with a malicious Telegram bot, sensitive data can be stolen, and attackers can gain remote control over the infected machine. This can allow attackers to move laterally within the network, compromise additional systems, and ultimately achieve their objectives, such as financial theft or intellectual property theft.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious Telegram DNS Queries` to your SIEM to identify unauthorized Telegram API usage (reference: `Detect Suspicious Telegram DNS Queries`).
*   Investigate any processes other than `telegram.exe` that resolve `api.telegram.org` (reference: IOC - `api.telegram.org`).
*   Monitor network connections to Telegram's infrastructure from unusual processes (reference: `Detect Suspicious Telegram Network Connections`).
*   Implement network-level blocking of connections to `api.telegram.org` from unauthorized systems.
*   Ensure Sysmon is installed and configured to capture DNS query events (EventID 22) and process creation events.
