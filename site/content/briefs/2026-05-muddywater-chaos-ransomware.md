---
title: MuddyWater Disguises Cyber-Espionage as Chaos Ransomware Attack
slug: 2026-05-muddywater-chaos-ransomware
description: The MuddyWater group is disguising its cyber-espionage operations as Chaos ransomware attacks, using Microsoft Teams social engineering for initial access and establishing persistence, likely to complicate attribution and mask their true objectives.
date: "2026-05-07T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - MuddyWater
tags:
  - muddywater
  - chaos ransomware
  - cyberespionage
  - data theft
  - iranian apt
vendors:
  - Microsoft
products:
  - Microsoft Teams
  - Microsoft Quick Assist
  - Microsoft WebView2
  - AnyDesk
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.bleepingcomputer.com/news/security/muddywater-hackers-use-chaos-ransomware-as-a-decoy-in-attacks/
rules:
  - title: Detect MuddyWater Backdoor Deployment
    description: Detects the deployment of the MuddyWater custom backdoor (Game.exe) via a malware loader (ms_upd.exe), often disguised as a Microsoft WebView2 application.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious AnyDesk Usage
    description: Detects suspicious use of AnyDesk, often associated with remote access by malicious actors.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

MuddyWater, an Iranian state-sponsored cyber-espionage group known for aligning with the country's Ministry of Intelligence and Security (MOIS), is disguising its operations as Chaos ransomware attacks. Starting in 2025, they have used Microsoft Teams social engineering to gain initial access and establish persistence within targeted organizations. The attackers engage in credential theft, data exfiltration, and extortion emails, while also making an entry on the Chaos leak portal. Rapid7 researchers believe the ransomware component serves as a decoy to complicate attribution and conceal their true cyber-espionage objectives. The group has previously deployed ransomware, such as Qilin in late 2025, to mask their activities, possibly pivoting to Chaos to avoid attribution following the Qilin incident.

## Attack Chain

1.  The attackers initiate chats with employees via Microsoft Teams, using social engineering to establish screen-sharing sessions.
2.  Credential theft occurs via phishing pages masquerading as Microsoft Quick Assist or by tricking victims into typing their passwords into local text files.
3.  Compromised accounts are used to authenticate to internal systems, including the domain controller.
4.  Persistence is established using RDP, DWAgent, and AnyDesk for remote access to the compromised systems.
5.  A malware loader (ms_upd.exe) is used to drop a custom backdoor (Game.exe), disguised as a Microsoft WebView2 application.
6.  The backdoor malware performs anti-analysis and anti-VM checks.
7.  The backdoor supports 12 commands, including PowerShell and CMD command execution, file upload and deletion, and persistent shell access.
8.  Data exfiltration occurs alongside the deployment of Chaos ransomware and an extortion attempt, likely to obfuscate the true objective of cyber espionage.

## Impact

The MuddyWater group's activities can lead to significant data breaches, system compromise, and potential financial losses for targeted organizations. While the Chaos ransomware component suggests a financial motive, the primary goal is believed to be cyber espionage aligned with the interests of the Iranian government. Past operations attributed to MuddyWater have targeted organizations in various sectors, and this shift to using ransomware as a decoy could broaden their target scope. If successful, these attacks can result in the theft of sensitive information, disruption of critical services, and reputational damage.

## Recommendation

*   Monitor process creations for `ms_upd.exe` dropping `Game.exe`, disguised as a Microsoft WebView2 application, and deploy the Sigma rule "Detect MuddyWater Backdoor Deployment" to identify this activity.
*   Monitor network connections for processes associated with AnyDesk and DWAgent, and review for unusual network connections to external IP addresses to detect persistence mechanisms.
*   Implement and enforce multi-factor authentication (MFA) to mitigate the impact of credential theft, and educate employees on the risks of social engineering via Microsoft Teams to prevent initial access.
