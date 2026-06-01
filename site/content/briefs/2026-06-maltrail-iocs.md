---
title: Maltrail IOC List Analysis - June 1, 2026
slug: 2026-06-maltrail-iocs
description: This brief analyzes a Maltrail IOC list from June 1, 2026, identifying domains and IP addresses associated with various malware and threat actors, including android_fvncbot, lummac2, magentocore, sectoprat, apt_lazarus, offloader, android_joker, cyberstrikeai, and nightshadec2, potentially used for command and control, malware distribution, or phishing campaigns.
date: "2026-06-01T10:09:24Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - maltrail
  - ioc
  - malware
  - command-and-control
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.circl.lu/doc/misp/feed-osint/e23472df-ca0e-42e3-a1d8-903fef202593.json
iocs:
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/484a67f82c9fb6aee55dfbbe865032e4b3c81fda
  - type: domain
    value: bbople.icu
  - type: domain
    value: cdn.yybane.icu
  - type: domain
    value: erggan.icu
  - type: domain
    value: uunuyi.icu
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/2b9b6ebebaecced2a25887a8cf51a9f1694d50ce
  - type: domain
    value: hardsmi.cyou
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/2057cc51864653becaf294ed2f4c36035dd70384
  - type: domain
    value: fbclickgo.win
  - type: domain
    value: fbids.com
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/8cd965be64c35bc228b269bcaa2bf34c2098ea55
  - type: ip
    value: 188.137.254.82
  - type: ip
    value: 193.233.82.76
  - type: ip
    value: 89.124.108.104
  - type: ip
    value: 89.124.99.84
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/b1b1344523bb6d1dbaa289536850160ad3fa76e0
  - type: ip
    value: 147.124.211.143
  - type: ip
    value: 147.124.212.178
  - type: ip
    value: 147.124.212.180
  - type: ip
    value: 147.124.212.207
  - type: ip
    value: 176.9.174.137
  - type: ip
    value: 37.48.102.17
  - type: ip
    value: 45.43.11.214
  - type: ip
    value: 66.235.168.158
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/80f920f0722b5e0119e623a821bf8ca87d57e468
  - type: domain
    value: crowddaughter.info
  - type: domain
    value: quarterants.xyz
  - type: domain
    value: supportbottle.info
  - type: domain
    value: volcanosisters.xyz
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/db96fead13ebcfdce283f6c938561ab5222d7c36
  - type: domain
    value: cepeek.yoga
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/366a806dc553ea1a326db541ce4bac4dc5c3e6d5
  - type: domain
    value: maxoria.cyou
  - type: domain
    value: sraspadinhagratuito2026.cyou
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/0b35c7b4b34c4899425eab70294fb1c141ab8efa
  - type: url
    value: https://app.validin.com/detail?find=edc16e04a8ca23706e25&type=hash&ref_id=b74105f13c2#tab=host_pairs
  - type: domain
    value: a9v8p0.cloudmellow.cc
  - type: domain
    value: adjust-work.cc
  - type: domain
    value: adjust-work.help
  - type: domain
    value: adjust-work.one
  - type: domain
    value: adjust-work.qpon
  - type: domain
    value: adjust-work.rest
  - type: domain
    value: b9r8y5.laseo.top
  - type: domain
    value: circuitcoiltech.com
  - type: domain
    value: cloudmellow.cc
  - type: domain
    value: emjratezdraw.com
  - type: domain
    value: flavorforgekitchencom.com
  - type: domain
    value: getaivira.com
  - type: domain
    value: homelabss.com
  - type: domain
    value: laseo.top
ioc_counts:
  domain: 28
  ip: 12
  url: 10
rules:
  - title: Detect Outbound Connection to Maltrail IOC - Domain
    description: Detects outbound network connections to domains identified in the Maltrail IOC list.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071
    data_sources:
      - network_connection
      - windows
  - title: Detect Outbound Connection to Maltrail IOC - IP Address
    description: Detects outbound network connections to IP addresses identified in the Maltrail IOC list.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This brief examines a set of indicators of compromise (IOCs) published by CIRCL-MISP in their Maltrail feed on June 1, 2026. The IOCs consist of domains and IP addresses identified as potentially malicious. These indicators are associated with various malware families and threat actors, including android_fvncbot, lummac2, magentocore, sectoprat, apt_lazarus, offloader, android_joker, cyberstrikeai, and nightshadec2. While the specific campaigns or malware variants employing these indicators are not detailed, the broad association with known threat actors and malware families suggests potential command and control (C2) infrastructure, malware distribution networks, or phishing campaign infrastructure. Defenders should proactively monitor for these indicators in network traffic and DNS logs to identify potential compromise.

## Attack Chain

Given the nature of the IOCs, the following attack chain is inferred:

1.  **Initial Access:** The attacker may gain initial access through various methods, such as phishing emails, drive-by downloads, or exploiting vulnerabilities in public-facing applications.
2.  **Malware Delivery:** Upon successful initial access, the attacker deploys malware onto the compromised system. This malware may be delivered directly or through a multi-stage process using droppers or loaders.
3.  **Command and Control (C2) Communication:** The malware establishes communication with a C2 server, often using the domains listed in the IOCs. This communication allows the attacker to remotely control the compromised system.
4.  **Persistence:** The attacker establishes persistence on the compromised system to maintain access even after reboots or system updates.
5.  **Lateral Movement:** The attacker attempts to move laterally within the network, compromising additional systems and escalating privileges.
6.  **Data Exfiltration:** The attacker identifies and exfiltrates sensitive data from the compromised network to a remote server controlled by the attacker.
7.  **Final Objective:** Depending on the attacker's motives, the final objective may include data theft, financial gain (e.g., ransomware), espionage, or disruption of services.
8.  **Infrastructure Hardening:** The attacker may use infrastructure such as the domains and IPs to facilitate ongoing attacks and evade detection.

## Impact

The successful deployment of malware and establishment of C2 communication can lead to significant damage. This can include data breaches, financial losses, reputational damage, and disruption of critical services. The variety of threat actors and malware families associated with these IOCs suggests a broad range of potential impacts, from targeted attacks by APT groups like Lazarus to widespread malware infections.

## Recommendation

*   Monitor network traffic and DNS queries for connections to the domains listed in the IOC table to identify potential C2 communication or malware activity.
*   Block the IP addresses listed in the IOC table at the firewall to prevent communication with known malicious hosts.
*   Deploy the Sigma rule "Detect Outbound Connection to Maltrail IOC" to identify potential C2 communication based on connections to the identified domains and IPs.
*   Investigate any systems communicating with the identified IOCs to determine the extent of the compromise and take appropriate remediation steps.
*   Implement robust endpoint detection and response (EDR) solutions to detect and prevent malware infections.
