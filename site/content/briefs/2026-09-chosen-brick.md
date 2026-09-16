---
title: 'Iranian State-Sponsored Surveillance Malware: Chosen Brick'
slug: 2026-09-chosen-brick
description: Iranian state-sponsored actors are leveraging the 'Chosen Brick' Windows malware to conduct surveillance on global activists and journalists via social engineering and Telegram-based command-and-control.
date: "2026-09-16T12:51:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - surveillance
  - nation-state
  - windows
  - espionage
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The attack chain typically begins on messaging platforms such as WhatsApp and Telegram.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Chosen Brick establishes persistence across reboots using registry Run keys.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: attempts to evade local security tools by adding exclusions in Microsoft Defender.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: For command-and-control (C&C) operations, the malware assigns each infected endpoint a unique Telegram bot ID.
    confidence_band: high
rules:
  - title: Detect Chosen Brick Persistence via Registry Run Key
    description: Detects potential persistence mechanism used by Chosen Brick by monitoring for additions to Windows Run keys
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy registry persistence detection rule to all Windows endpoints
      owner: Detection Engineering
      due: 24h
      evidence: Chosen Brick persistence TTP
  hunt_leads:
    - lead: Search for unknown processes initiating outbound connections to api.telegram.org
      technique_id: T1071
      data_needed:
        - Network connection logs / Proxy logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Malware utilizes Telegram for C2
  mitigation_plan:
    - priority: immediate
      action: Enable attack surface reduction rules to block persistence mechanisms and unauthorized Defender exclusions
      owner: IT Operations
      addresses: Persistence and Defense Evasion TTPs
      evidence: Source reporting on Chosen Brick TTPs
---

Since at least 2025, Iranian state-sponsored actors have deployed a Windows-based surveillance malware family dubbed 'Chosen Brick' to target dissidents, activists, and journalists worldwide. The threat actors engage targets through messaging platforms like WhatsApp and Telegram, often masquerading as acquaintances or technical support personnel to build rapport. The campaign focuses on harvesting sensitive data, including contact lists, emails, and social media messages, to track the targets' physical location and life patterns. In instances where corporate security controls prevent initial infection, the actors actively maneuver the target toward using personal devices to bypass enterprise-grade protections. The surveillance data is subsequently used for harassment, with stolen information occasionally posted to pro-Iranian leak sites to intimidate victims.

## Attack Chain

1. Initial contact is established via messaging platforms (WhatsApp or Telegram) using social engineering to build trust.
2. Attackers deliver weaponized files disguised as legitimate utility software or medical documentation (e.g., MRI scan results).
3. The victim executes the malicious file, which triggers a decoy document while the malware runs in the background.
4. Chosen Brick establishes persistence on the host by creating entries in Windows Registry Run keys.
5. The malware performs defense evasion by programmatically adding itself to Microsoft Defender exclusion lists.
6. The malware registers with a unique Telegram bot ID to initiate C2 communication.
7. The operator exfiltrates data or executes secondary payloads to gain further control over the host.

## Impact

The Chosen Brick campaign represents a targeted surveillance operation supporting state-sponsored repression. Victims include individuals perceived as threats to the Iranian regime, such as journalists and activists. The malware enables comprehensive spying capabilities including microphone audio recording, screenshot capture, credential harvesting from browser data, and data wiping. The public release of stolen personal information on leak sites has been observed as a tactic to harass and silence targeted individuals.

## Recommendation

* Deploy the provided Sigma rule to detect suspicious Registry Run key modifications that attempt to facilitate malware persistence.
* Monitor for unauthorized modifications to Microsoft Defender exclusion lists via Group Policy or local security log auditing.
* Enhance endpoint visibility to detect unusual communication patterns associated with Telegram bot API endpoints (api.telegram.org) from non-browser processes.
* Advise personnel to avoid opening files from unverified messaging platform contacts and discourage the use of personal devices for accessing sensitive corporate communications.
