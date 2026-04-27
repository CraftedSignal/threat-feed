---
title: Potential Abuse of msDS-ManagedAccountPrecededByLink for Privilege Escalation
slug: 2024-01-30-dmsa-link-mod
description: Detection of PowerShell scripts modifying the msDS-ManagedAccountPrecededByLink attribute, potentially indicating exploitation of the BadSuccessor privilege escalation vulnerability in Windows Server 2025.
date: "2026-03-30T10:27:13Z"
severities:
  - medium
tags:
  - privilege-escalation
  - defense-evasion
  - persistence
  - initial-access
  - active-directory
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://www.akamai.com/blog/security-research/abusing-bad-successor-for-privilege-escalation-in-active-directory
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_modification_of_dmsa_link_attribute.yml
rules:
  - title: DMSA Link Attribute Modification via PowerShell
    description: Detects modification of dMSA link attributes (msDS-ManagedAccountPrecededByLink) via PowerShell scripts.
    platform: sigma
    severity: low
    tactics:
      - defense-evasion
      - initial-access
      - persistence
      - privilege-escalation
    techniques:
      - T1078.002
      - T1098
    data_sources:
      - ps_script
      - windows
  - title: Suspicious PowerShell Script with msDS-ManagedAccountPrecededByLink
    description: Detects PowerShell scripts containing 'msDS-ManagedAccountPrecededByLink' that might indicate malicious activity.
    platform: sigma
    severity: informational
    tactics:
      - defense-evasion
      - initial-access
      - persistence
      - privilege-escalation
    techniques:
      - T1078.002
      - T1098
    data_sources:
      - ps_script
      - windows
rules_count: 2
---

This threat brief focuses on the modification of the `msDS-ManagedAccountPrecededByLink` attribute within Active Directory via PowerShell scripts. This activity is flagged as potentially malicious because it could be indicative of an attempt to exploit the 'BadSuccessor' privilege escalation vulnerability in Windows Server 2025. The vulnerability, as outlined in Akamai's research, allows attackers to manipulate managed service account (dMSA) links to gain elevated privileges. The detection is…
