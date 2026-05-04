---
title: Potential Masquerading as Communication Apps
slug: 2024-01-masquerading-communication-apps
description: Attackers may attempt to evade defenses by masquerading malicious processes as legitimate communication applications such as Slack, WebEx, Teams, Discord, RocketChat, Mattermost, WhatsApp, Zoom, Outlook and Thunderbird.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - masquerading
  - windows
vendors:
  - Slack Technologies
  - Cisco
  - Microsoft
  - Discord
  - Rocket.Chat Technologies
  - Mattermost
  - WhatsApp
  - Zoom Video Communications
  - Mozilla
products:
  - Slack
  - WebEx
  - Teams
  - Discord
  - Rocket.Chat
  - Mattermost
  - WhatsApp
  - Zoom
  - Outlook
  - Thunderbird
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1554
    technique_name: Compromise Host Software Binary
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_masquerading_communication_apps.toml
rules:
  - title: Potential Masquerading as Communication Apps - Generic
    description: Detects unsigned or improperly signed processes masquerading as communication applications by checking the process name and code signature status.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.001
    data_sources:
      - process_creation
      - windows
  - title: Potential Masquerading as Communication Apps - Specific
    description: Detects unsigned or improperly signed instances of specific communication applications by checking the process name and code signature subject name.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may attempt to evade defenses by masquerading malicious processes as legitimate communication applications. This involves using names and icons that resemble trusted applications like Slack, WebEx, Teams, Discord, RocketChat, Mattermost, WhatsApp, Zoom, Outlook and Thunderbird to trick users and bypass security measures. This technique can be used to conceal malicious activity, bypass allowlists, or trick users into executing malware. The detection rule identifies suspicious instances by checking for unsigned or improperly signed processes, ensuring they match known trusted signatures, which helps in flagging potential threats that mimic trusted communication tools.

## Attack Chain

1. An attacker gains initial access to a Windows system through various means such as phishing or exploiting a vulnerability.
2. The attacker deploys a malicious executable onto the compromised system.
3. The attacker renames the malicious executable to resemble a legitimate communication application, such as "slack.exe" or "Teams.exe".
4. The attacker modifies or removes the code signature of the malicious executable to avoid detection based on trusted publishers.
5. The attacker executes the renamed and potentially unsigned malicious executable.
6. The masqueraded process performs malicious actions, such as establishing a reverse shell or downloading additional payloads.
7. The attacker uses the compromised system to move laterally within the network, escalating privileges and compromising additional systems.
8. The final objective is to exfiltrate sensitive data or deploy ransomware.

## Impact

Successful masquerading attacks can lead to significant security breaches, including data theft, system compromise, and financial loss. By disguising malicious processes as legitimate communication apps, attackers can bypass security controls and operate undetected for extended periods. This can result in widespread damage and disruption, as well as reputational damage for the targeted organization. The impact can range from a few compromised systems to a complete network takeover, depending on the attacker's objectives and the effectiveness of the masquerading technique.

## Recommendation

*   Deploy the Sigma rule "Potential Masquerading as Communication Apps - Generic" to your SIEM and tune for your environment to detect unsigned or improperly signed communication applications.
*   Deploy the Sigma rule "Potential Masquerading as Communication Apps - Specific" to your SIEM and tune for your environment to detect unsigned or improperly signed instances of specific communication applications.
*   Enable process creation logging on Windows systems to capture the necessary events for the Sigma rules.
*   Review and validate the code signatures of all communication apps on your systems to ensure they are properly signed by trusted entities.
*   Implement application control policies to restrict the execution of unsigned or untrusted executables.
