---
title: Suspicious Domain Managed Service Account Creation by Unusual User
slug: 2024-01-dmsa-privesc
description: Detection of a Domain Managed Service Account (DMSA) creation event by a user that typically does not perform this administrative task, potentially indicating privilege escalation or account compromise.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - active-directory
  - dmsa
vendors:
  - Microsoft
products:
  - Windows Server
  - Active Directory
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/privilege_escalation_dmsa_creation_by_unusual_user.toml
rules:
  - title: DMSA Creation by Unusual User via PowerShell
    description: Detects the creation of a Domain Managed Service Account (DMSA) using PowerShell by a user that is not typically associated with this activity.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: DMSA Creation Event via AD Management Tools
    description: Detects events related to the creation of a Domain Managed Service Account (DMSA) through standard Active Directory management tools executed by an unusual user.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This alert focuses on detecting anomalous creation of Domain Managed Service Accounts (DMSAs) within a Windows environment. DMSAs are privileged accounts used to run services and applications. The creation of these accounts should typically be restricted to a small set of administrators. When a user outside of this group creates a DMSA, it could indicate malicious activity such as privilege escalation, lateral movement from a compromised account, or an insider threat. This detection aims to identify unusual DMSA creation events, helping security teams quickly investigate and respond to potential security breaches. The rule is based on identifying deviations from the norm in terms of who is creating these accounts.

## Attack Chain

1. An attacker gains initial access to a low-privilege user account, possibly through phishing or password compromise.
2. The attacker performs reconnaissance to identify potential privilege escalation paths within the domain.
3. The attacker attempts to create a DMSA using tools like `New-ADServiceAccount` PowerShell cmdlet or AD management tools.
4. The attacker leverages the newly created DMSA to gain elevated privileges within the network.
5. The attacker uses the compromised DMSA to access sensitive resources or systems.
6. The attacker may install malware or backdoors on critical systems using the DMSA credentials.
7. The attacker may then perform lateral movement to compromise additional systems and escalate privileges further.

## Impact

A successful DMSA creation by an unauthorized user can lead to significant privilege escalation within the Active Directory domain. This can provide attackers with administrative control over critical systems and data, enabling them to steal sensitive information, disrupt services, and potentially deploy ransomware across the entire organization. The scope of the attack can be broad, potentially affecting all systems and users within the domain.
