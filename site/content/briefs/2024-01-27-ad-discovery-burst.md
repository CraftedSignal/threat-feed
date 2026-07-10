---
title: Pre-Ransomware Active Directory Discovery Burst
slug: 2024-01-27-ad-discovery-burst
description: Attackers perform a burst of Active Directory discovery commands on a Windows host to gather information prior to ransomware deployment.
date: "2024-01-27T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - active-directory
  - discovery
  - ransomware
  - windows
vendors:
  - Microsoft
products:
  - Windows
  - Active Directory
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087.002
    technique_name: 'Account Discovery: Domain Account'
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1482
    technique_name: Domain Trust Discovery
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rb8vmb/preransomware_ad_discovery_burst_detection_in/
rules:
  - title: Detect Multiple Discovery Commands in Short Timeframe
    description: Detects a burst of common discovery commands within a short timeframe, indicating potential reconnaissance activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - process_creation
      - windows
  - title: Detect nltest Usage for Domain Trust Discovery
    description: Detects the use of nltest.exe with the /domain_trusts flag to enumerate domain trusts.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1482
    data_sources:
      - process_creation
      - windows
  - title: Detect 'net' command execution for user enumeration
    description: Detects execution of net.exe to enumerate domain users
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1087.002
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This threat brief focuses on detecting a burst of Active Directory (AD) discovery commands executed on a Windows host, an indicator of pre-ransomware activity. Attackers often perform reconnaissance to map the AD environment, identify high-value targets, and discover privileged accounts before deploying ransomware. This activity typically occurs early in the attack chain. The commands observed include `systeminfo`, `nltest`, `net.exe`, and `whoami`. Detecting this pattern can provide early warning, allowing defenders to disrupt the attack before encryption occurs. The focus is on using process tree analysis and follow-on activity to differentiate between legitimate administrator behavior and malicious intent, escalating the severity of alerts when user or group changes are detected after the discovery phase.

## Attack Chain

1.  The attacker gains initial access to a Windows host within the target network (initial access method not specified).
2.  The attacker executes `systeminfo` to gather detailed information about the compromised host, including OS version, hardware configuration, and installed software.
3.  The attacker executes `nltest /domain_trusts` to enumerate domain trusts and identify potential lateral movement paths.
4.  The attacker uses `net.exe` commands (e.g., `net user /domain`, `net group /domain`) to enumerate users, groups, and domain administrators.
5.  The attacker executes `whoami /all` to identify the current user's privileges and group memberships.
6.  The attacker analyzes the gathered information to identify privileged accounts and potential targets for lateral movement.
7.  The attacker attempts to escalate privileges or move laterally to other systems within the network (technique unspecified).
8.  The attacker deploys ransomware to encrypt critical systems and demand a ransom payment.

## Impact

A successful attack can lead to widespread encryption of systems, data loss, and significant business disruption. Organizations in various sectors are at risk. The financial impact can range from downtime and recovery costs to reputational damage and regulatory fines. Early detection of AD discovery activity can significantly reduce the impact of a ransomware attack by providing defenders with the opportunity to isolate affected systems and prevent further lateral movement. Without early detection, the attacker could successfully encrypt hundreds or even thousands of systems.
