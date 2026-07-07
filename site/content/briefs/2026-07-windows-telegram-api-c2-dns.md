---
title: Windows DNS Query to Telegram Bot API Indicating Malware C2
slug: 2026-07-windows-telegram-api-c2-dns
description: This brief details the detection of suspicious DNS queries from non-Telegram processes to api.telegram.org on Windows systems, a strong indicator of malware utilizing the Telegram Bot API for command and control (C2) communications to receive commands or exfiltrate data.
date: "2026-07-03T13:28:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - network
  - command-and-control
  - c2
  - telegram
  - windows
  - malware
vendors:
  - Telegram
products:
  - Telegram Bot API
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The analytic detects the execution of a DNS query by a process to the associated Telegram API domain, which could indicate access via a Telegram bot commonly used by malware for command and control (C2) communications.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
    evidence: This behavior is often observed in cyberattacks where Telegram bots are used to receive commands or exfiltrate data, making it a key indicator of suspicious or malicious activity within a network.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/network/windows_dns_query_request_by_telegram_bot_api.yml
  - https://www.splunk.com/en_us/blog/security/threat-advisory-telegram-crypto-botnet-strt-ta01.html
iocs:
  - type: domain
    value: api.telegram.org
ioc_counts:
  domain: 1
rules:
  - title: Windows DNS Query to Telegram Bot API by Non-Telegram Process
    description: Detects DNS queries to api.telegram.org from processes other than the legitimate Telegram client, indicating potential malware C2 via Telegram Bot API.
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
rules_count: 1
---

This intelligence describes a detection opportunity for malicious activity on Windows endpoints where processes other than the legitimate Telegram client attempt to resolve `api.telegram.org`. This domain is the primary endpoint for the Telegram Bot API, which is frequently abused by various malware families for command and control (C2) communications. By monitoring for these specific DNS queries, security teams can identify potential covert communication channels established by malware on compromised systems. This technique allows attackers to send commands to compromised machines, receive exfiltrated data, or maintain persistence, bypassing traditional firewall rules that might block direct C2 traffic to unknown IP addresses but permit access to legitimate cloud services. The detection logic specifically targets `Sysmon Event ID 22` (DNS Query) and excludes `telegram.exe` to reduce false positives.

## Impact

If this activity goes undetected, it indicates that a system within the network is likely compromised by malware leveraging the Telegram Bot API for C2. The successful establishment of this communication channel allows attackers to maintain control over the compromised endpoint. This can lead to further stages of the attack chain, including data exfiltration, deployment of additional malicious payloads (such as ransomware or crypto-miners), remote execution of commands, or lateral movement within the network. The observed damage typically includes data theft, system manipulation, and potential financial losses for the affected organization.

## Recommendation

*   Deploy the Sigma rule "Windows DNS Query to Telegram Bot API by Non-Telegram Process" to your SIEM and tune for your environment.
*   Ensure Sysmon Event ID 22 (DNS Query) logging is enabled and ingested into your security monitoring platform to activate the rule above.
*   Consider blocking or strictly monitoring `api.telegram.org` at the network perimeter (DNS resolver, proxy) for all systems not explicitly authorized to use the Telegram Bot API, as listed in the IOC table.
