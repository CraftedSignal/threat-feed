---
title: Windows DNS Query Request by Telegram Bot API
slug: 2026-07-telegram-bot-api-c2
description: An analytic detects DNS queries to `api.telegram.org` originating from non-Telegram processes on Windows systems, indicating potential malware command and control (C2) communication or data exfiltration via the Telegram Bot API.
date: "2026-07-24T09:08:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - malware
  - windows
  - c2
  - dns
  - telegram
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
    evidence: By monitoring DNS queries related to Telegram's infrastructure, the detection identifies potential attempts to establish covert communication channels between a compromised system and external malicious actors. This behavior is often observed in cyberattacks where Telegram bots are used to receive commands or exfiltrate data, making it a key indicator of suspicious or malicious activity within a network.
    confidence_band: high
references:
  - https://www.splunk.com/en_us/blog/security/threat-advisory-telegram-crypto-botnet-strt-ta01.html
iocs:
  - type: domain
    value: api.telegram.org
ioc_counts:
  domain: 1
rules:
  - title: Detect DNS Query Request by Non-Telegram Process to Telegram Bot API
    description: Detects DNS queries made by non-Telegram processes to the api.telegram.org domain, indicating potential malware command and control (C2) communication via the Telegram Bot API.
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

This brief highlights a detection for malicious activity where processes other than the legitimate Telegram application make DNS queries to `api.telegram.org`. This behavior is a strong indicator of malware leveraging the Telegram Bot API for command and control (C2) communications or data exfiltration on compromised Windows systems. Threat actors frequently exploit popular, legitimate communication platforms like Telegram to blend malicious traffic with normal network activity, making detection challenging. This specific analytic focuses on identifying suspicious DNS lookups to Telegram's API domain by unauthorized processes, signaling a potential covert communication channel established by malware. Attackers utilize these channels to issue commands, download additional payloads, or exfiltrate sensitive data from the victim's network, representing a post-exploitation phase in a broader cyberattack.

## Attack Chain

1. **Initial Access**: (Not detailed in source, but implied by malware presence.) An attacker gains initial access to a Windows system through various means (e.g., phishing, exploit, compromised credentials).
2. **Execution**: Malware is executed on the compromised system.
3. **Command and Control (C2) Setup**: The malware attempts to establish communication with its C2 server.
4. **DNS Query for C2**: The malware process performs a DNS query for `api.telegram.org` to resolve the Telegram Bot API endpoint.
5. **Covert Communication**: The malware utilizes the Telegram Bot API as a C2 channel to receive commands or exfiltrate data, bypassing traditional network controls by leveraging a legitimate service.
6. **Impact**: Depending on commands received, the malware can lead to data theft, further system compromise, or ransomware deployment.

## Impact

Successful exploitation where malware utilizes the Telegram Bot API for C2 or data exfiltration can lead to severe consequences. Attackers can maintain persistent access to the compromised system, exfiltrate sensitive company data, deploy additional malicious payloads such as ransomware or other destructive tools, or pivot to other systems within the network. This covert communication method significantly increases the difficulty of detecting and containing breaches, potentially leading to financial losses, reputational damage, and regulatory penalties. The specific number of victims or sectors is not detailed, but such C2 methods are common across various industries.

## Recommendation

* Enable Sysmon Event ID 22 for DNS query logging on all Windows endpoints to gather the necessary telemetry for detection.
* Deploy the Sigma rule provided in this brief to your SIEM and tune for your environment to detect suspicious DNS queries.
* Monitor network connections and DNS queries to the `api.telegram.org` domain, especially from processes other than legitimate Telegram clients.
