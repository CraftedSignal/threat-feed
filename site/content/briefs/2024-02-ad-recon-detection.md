---
title: Detecting Pre-Ransomware Active Directory Reconnaissance
slug: 2024-02-ad-recon-detection
description: Adversaries perform Active Directory reconnaissance using built-in tools like nltest, whoami, and net.exe to map the environment before deploying ransomware.
date: "2024-02-21T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - active-directory
  - reconnaissance
  - ransomware
vendors:
  - Microsoft
products:
  - Active Directory
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Standard Permissions Groups Discovery
references:
  - https://www.reddit.com/r/cybersecurity/comments/1rb9il6/preransomware_discovery_detection_with_sigma/
rules:
  - title: Detect Active Directory Enumeration via Nltest
    description: Detects the use of nltest.exe to enumerate domain trusts, a common reconnaissance technique.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - process_creation
      - windows
  - title: Detect Group Enumeration via Whoami
    description: Detects the use of whoami.exe to enumerate group memberships.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1069.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Group Enumeration via Net.exe
    description: Detects the use of net.exe to enumerate domain groups.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1069.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This threat brief focuses on detecting pre-ransomware reconnaissance activity targeting Active Directory. Attackers often use readily available tools to gather information about the domain, user accounts, and group memberships before deploying ransomware. This activity is often performed in short bursts to minimize detection. The techniques involve common commands like `nltest`, `whoami /groups`, and `net.exe group` executed from compromised endpoints. Identifying these reconnaissance attempts early can provide defenders with a crucial opportunity to disrupt the attack before ransomware is deployed and significant damage is inflicted. Monitoring for these specific command sequences, especially when followed by suspicious user creation or privileged group modifications, is critical for early threat detection and mitigation.

## Attack Chain

1.  An attacker compromises a user account or endpoint within the target network through unknown means (e.g., phishing, exploit).
2.  The attacker executes `nltest /domain_trusts` to enumerate domain trusts and map the Active Directory environment.
3.  The attacker executes `whoami /groups` to identify the groups the compromised user belongs to.
4.  The attacker uses `net group /domain` to enumerate domain groups.
5.  The attacker uses `net group "Domain Admins" /domain` to identify members of the Domain Admins group.
6.  Based on gathered information, the attacker attempts to escalate privileges, potentially creating new user accounts with elevated permissions.
7.  The attacker adds the newly created or compromised accounts to privileged groups like "Domain Admins".
8.  The attacker leverages the gained privileges to deploy ransomware across the network.

## Impact

Successful Active Directory reconnaissance allows attackers to map the network environment, identify critical assets, and escalate privileges. This leads to widespread ransomware deployment, data encryption, and significant business disruption. Organizations can experience financial losses due to downtime, data recovery costs, and potential ransom payments. The impact can range from temporary service outages to permanent data loss and reputational damage, affecting potentially thousands of users and systems across the organization.
