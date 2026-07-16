---
title: UAT-11795 Deploys Starland RAT and WLDR Agent via Trojanized Software
slug: 2026-07-uat-11795-starland-rat
description: UAT-11795, a sophisticated and financially motivated Russian-speaking threat actor, targets users in the U.S. and Europe with trojanized software installers to deploy custom Python-based Starland RAT and an in-memory PowerShell WLDR agent for credential theft and cryptocurrency exfiltration.
date: "2026-07-16T18:03:04Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - UAT-11795
exploited: true
tags:
  - financially-motivated
  - rat
  - c2
  - trojan
  - windows
  - python
  - powershell
vendors:
  - Cisco
  - Zoom Video Communications
  - Mobatek
products:
  - Webex
  - Zoom
  - MobaXterm
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: UAT-11795 uses trojanized software installers — including popular tools like Webex, Zoom, and MobaXterm — to deliver a custom Python-based remote access tool
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: most notably a bespoke, in-memory PowerShell command-and-control (C2) implant known as the 'WLDR agent'
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: UAT-11795 employs highly evasive techniques, including AMSI and ETW bypasses
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: uses a clever blockchain-anchored fallback mechanism to maintain persistent command and control
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: deploy secondary payloads like CastleStealer and Remcos RAT to siphon high-value credentials
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: siphon high-value credentials and cryptocurrency assets
    confidence_band: high
references:
  - https://blog.talosintelligence.com/begun-the-patch-wars-have/
  - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign
  - https://www.bleepingcomputer.com/news/microsoft/microsoft-july-2026-patch-tuesday-fixes-massive-570-flaws-3-zero-days/
rules:
  - title: Detect Suspicious Mshta.exe Execution
    description: Detects suspicious execution of mshta.exe, often used by adversaries for arbitrary code execution, especially for fetching and executing remote scripts or HTA files.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious PowerShell In-Memory or Encoded Commands
    description: Detects common indicators of suspicious PowerShell activity, including the use of encoded commands or techniques often associated with in-memory execution, as seen in campaigns like UAT-11795.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Cisco Talos has disclosed details of a new campaign by UAT-11795, a sophisticated, financially motivated Russian-speaking adversary that has been active since at least June 2025. This threat actor targets individuals and organizations in the U.S. and Europe, leveraging trojanized software installers for popular applications such as Webex, Zoom, and MobaXterm to establish initial access. The primary payload is a custom Python-based remote access tool (RAT) dubbed "Starland RAT," which serves as a gateway for deploying further malicious implants. Notably, UAT-11795 deploys a bespoke, in-memory PowerShell command-and-control (C2) agent tracked as the "WLDR agent." The group employs highly evasive techniques, including AMSI and ETW bypasses, and utilizes a unique blockchain-anchored fallback mechanism to maintain persistent C2 communications. Once a foothold is established, UAT-11795 quickly deploys secondary payloads like CastleStealer and Remcos RAT to steal credentials and cryptocurrency assets.

## Attack Chain

1. **Initial Access**: UAT-11795 distributes trojanized software installers for popular applications, including Webex, Zoom, and MobaXterm. Victims are lured into downloading and executing these compromised installers, often through social engineering or unofficial download sources.
2. **Payload Delivery**: Upon execution, the trojanized installer deploys "Starland RAT," a custom Python-based remote access tool, onto the victim's system.
3. **Command and Control Establishment**: Starland RAT establishes initial command and control, acting as a primary gateway for further malicious activities and payload delivery.
4. **Secondary Payload Deployment**: The actor deploys a bespoke, in-memory PowerShell C2 implant known as the "WLDR agent," which operates directly in memory to evade detection.
5. **Defense Evasion & Resilient C2**: UAT-11795 employs advanced evasive techniques such as AMSI and ETW bypasses to hinder security analysis. They also establish a blockchain-anchored fallback mechanism to ensure persistent command and control, even if primary channels are disrupted.
6. **Credential Access**: Secondary payloads, including CastleStealer and Remcos RAT, are deployed to siphon high-value credentials from the compromised system.
7. **Data Exfiltration**: The final objective involves exfiltrating stolen credentials and cryptocurrency assets from the victim's environment, leading to financial gain for the adversary.

## Impact

This opportunistic campaign casts a wide net across multiple victim profiles, turning a simple software download into a full-blown compromise for individuals and corporate entities alike in the U.S. and Europe. Attackers are financially motivated, deploying secondary payloads like CastleStealer and Remcos RAT to siphon high-value credentials and cryptocurrency assets from victims. Successful compromise leads to significant data theft, potential financial loss, and sustained unauthorized access through persistent command and control mechanisms, posing a severe risk to affected organizations and individuals.

## Recommendation

* Deploy the Sigma rules in this brief to your SIEM and tune them for your environment to detect suspicious activity.
* Educate your users on social engineering tactics and the dangers of unofficial software downloads to prevent initial access by UAT-11795 via trojanized installers.
* Monitor for suspicious execution of `mshta.exe` and unusual PowerShell activity, particularly scripts executing from memory, using the provided Sigma rules to detect execution and defense evasion techniques.
* Ensure endpoint detection solutions are tuned to catch AMSI tampering and in-memory execution, indicators of UAT-11795's defense evasion.
