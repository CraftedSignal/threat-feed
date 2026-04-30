---
title: 'Maltrail IOCs Report: Tracking Multiple Threat Actors'
slug: 2026-02-maltrail-iocs
description: This brief analyzes IOCs aggregated by Maltrail on February 27, 2026, highlighting network activity associated with diverse threat actors including APT_UNC2465, Lazarus Group, Gorat, APT_Bitter, Android_Joker, PowerShell Injector, SmokeLoader, and FakeApp campaigns targeting various sectors.
date: "2026-02-27T23:00:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - maltrail
  - threat-intelligence
  - apt
  - malware
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1001
    technique_name: Data Obfuscation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://www.circl.lu/doc/misp/feed-osint/ca644701-62d1-4217-ada4-37452e8086db.json
  - https://api.github.com/repos/stamparm/maltrail/commits/0646683ef79252a23e46ab0f0c2f5cd19622153a
  - https://api.github.com/repos/stamparm/maltrail/commits/ef8592c301ca981ee5e763e64a2799a42dfb624a
  - https://api.github.com/repos/stamparm/maltrail/commits/9b786d496f9492f593d4f4d4d65f55da0fe1f8ee
  - https://api.github.com/repos/stamparm/maltrail/commits/a6a5d4fc2e913d96182c8ba9c1cf9296ae1d8c3e
  - https://api.github.com/repos/stamparm/maltrail/commits/3f6f94d4cbe5ca9362428adb4dee7084d1cdd24b
  - https://api.github.com/repos/stamparm/maltrail/commits/580ed2e5cc6de73363f5768a87fbdd3339dc2d7c
  - https://api.github.com/repos/stamparm/maltrail/commits/1aef6ec81fe3d2f652843e6dbe91455a2cd62f5c
  - https://api.github.com/repos/stamparm/maltrail/commits/fc046d4c30e9cf55674bf051ff38d5ddd5ded3d6
  - https://api.github.com/repos/stamparm/maltrail/commits/d80f240b6a29965ab001b54937bd0551badb89b4
  - https://api.github.com/repos/stamparm/maltrail/commits/0b2c6651676f745850e5150528d491647cdb0f53
  - https://api.github.com/repos/stamparm/maltrail/commits/032c33b2917a05e61f48ff99ab0faaf523441536
iocs:
  - type: domain
    value: rv-tools.info
  - type: domain
    value: online.zitlex.com
  - type: domain
    value: zitlex.com
  - type: domain
    value: msftconnecttest.xyz
  - type: domain
    value: a.msftconnecttest.xyz
  - type: domain
    value: asset.msftconnecttest.xyz
  - type: domain
    value: demo.msftconnecttest.xyz
  - type: domain
    value: test.msftconnecttest.xyz
  - type: ip
    value: 107.172.39.100
  - type: domain
    value: ashersoftlib.com
  - type: domain
    value: petitle.cloud
  - type: domain
    value: resistantmusic.shop
  - type: domain
    value: dax.estate
  - type: ip
    value: 185.82.202.150
  - type: ip
    value: 162.19.214.220
  - type: domain
    value: 162-19-214-220.eyeohost.net
  - type: domain
    value: 162.19.214.220.sslip.io
  - type: domain
    value: apostile.zapto.org
  - type: domain
    value: googletranslate.zapto.org
  - type: domain
    value: behnam.strangled.net
  - type: domain
    value: phoenixnetwork2.xyz
  - type: domain
    value: fontfix-chrome.com
  - type: domain
    value: alpha-glance-rz.tech
  - type: domain
    value: chromium-report-tech-331as-2s1-tcd-h143.alpha-glance-rz.tech
  - type: domain
    value: doji-board-raz.top
  - type: domain
    value: beekeeperstudio-db.com
  - type: domain
    value: beekeeperstudio.cc
ioc_counts:
  domain: 24
  ip: 3
rules:
  - title: Detect Network Connection to PowerShell Injector Domains
    description: Detects network connections to domains associated with PowerShell Injector campaigns, indicating potential command and control activity.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Network Connection to FakeApp Domains
    description: Detects network connections to domains associated with FakeApp campaigns, indicating potential communication with malicious infrastructure.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Network Connection to msftconnecttest Domains
    description: Detects network connections to domains used by the Gorat group, masquerading as Microsoft connection tests.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

This threat brief is based on an IOC feed from Maltrail, dated February 27, 2026, which aggregates indicators related to various threat actors and malware campaigns. The tracked actors include APT_UNC2465, Lazarus Group, Gorat, APT_Bitter, Android_Joker, PowerShell Injector, SmokeLoader, and FakeApp. The IOCs primarily consist of domains and IP addresses associated with these groups' network infrastructure and malware distribution. These campaigns are likely targeting a wide range of victims across multiple sectors, employing diverse techniques to achieve their objectives, including initial access, command and control, and potentially data exfiltration or deployment of malicious payloads. The data suggests ongoing malicious activity necessitating proactive monitoring and detection efforts.

## Attack Chain

1.  **Initial Compromise:** An unsuspecting user visits a compromised website or interacts with a malicious advertisement, potentially leading to the download of a malware loader such as those associated with SmokeLoader or FakeApp.
2.  **Malware Installation:** The initial loader executes on the victim's system, establishing persistence and preparing the environment for further malicious activities. This may involve creating scheduled tasks or modifying registry keys for auto-start.
3.  **Command and Control (C2) Communication:** The malware establishes communication with a command-and-control server, using domains such as `dax.estate` (SmokeLoader) or `resistantmusic.shop` (PowerShell Injector) to receive instructions and transmit data.
4.  **PowerShell Injection:** The PowerShell Injector, utilizes multiple techniques to inject malicious code into running processes, allowing it to evade detection and maintain persistence within the system. Domains such as `apostile.zapto.org` and `googletranslate.zapto.org` may resolve to infrastructure involved in command and control of compromised hosts.
5.  **Lateral Movement:** The attackers leverage compromised systems to move laterally within the network, potentially using stolen credentials or exploiting vulnerabilities to gain access to additional systems.
6.  **Data Exfiltration:** Sensitive data is collected from compromised systems and exfiltrated to attacker-controlled servers, potentially using domains such as `ashersoftlib.com` (APT_Bitter) for staging or exfiltration.
7.  **Android Exploitation:** In the case of Android_Joker, malicious applications distributed through unofficial channels or app stores communicate with `petitle.cloud` for command and control, potentially leading to data theft or installation of further malware.
8.  **Final Objective:** The final objective of the attack may vary depending on the actor and the target, ranging from data theft and espionage (APT_UNC2465, Lazarus Group, APT_Bitter) to financial gain (Android_Joker) or widespread malware distribution (SmokeLoader, FakeApp, PowerShell Injector).

## Impact

Compromised systems can be used for a variety of malicious purposes, including data theft, financial fraud, and further propagation of malware. Victims may experience data breaches, financial losses, and reputational damage. The wide range of threat actors involved suggests that various sectors and organizations are at risk. If successful, these attacks can lead to significant financial losses and disruption of business operations.

## Recommendation

*   Block the identified malicious domains and IP addresses at the network perimeter to prevent communication with command-and-control servers (IOC table).
*   Implement a web proxy filter to block access to URLs associated with malware downloads and phishing campaigns (IOC table).
*   Monitor network traffic for connections to known malicious domains and IP addresses associated with APT_Bitter, PowerShell Injector, SmokeLoader, and FakeApp (IOC table).
*   Deploy the Sigma rule to detect network connections to domains associated with PowerShell Injector infrastructure. Tune the rule for your environment (Sigma Rule).
*   Deploy the Sigma rule to detect network connections to infrastructure associated with FakeApp campaigns, adjusting the rule as needed for your environment (Sigma Rule).
*   Investigate and remediate any systems that exhibit suspicious network activity or have been identified as compromised based on the IOCs provided (IOC table).
