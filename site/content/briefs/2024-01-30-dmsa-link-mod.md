---
title: Potential Abuse of msDS-ManagedAccountPrecededByLink for Privilege Escalation
slug: 2024-01-30-dmsa-link-mod
description: Detection of PowerShell scripts modifying the msDS-ManagedAccountPrecededByLink attribute, potentially indicating exploitation of the BadSuccessor privilege escalation vulnerability in Windows Server 2025.
date: "2026-03-30T10:27:13Z"
type: advisory
types:
  - advisory
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

This threat brief focuses on the modification of the `msDS-ManagedAccountPrecededByLink` attribute within Active Directory via PowerShell scripts. This activity is flagged as potentially malicious because it could be indicative of an attempt to exploit the 'BadSuccessor' privilege escalation vulnerability in Windows Server 2025. The vulnerability, as outlined in Akamai's research, allows attackers to manipulate managed service account (dMSA) links to gain elevated privileges. The detection is based on identifying specific PowerShell script patterns that include `.Put("msDS-ManagedAccountPrecededByLink'` and `CN=`, which are used to modify these critical AD attributes. Defenders should be aware that legitimate administrative tasks might also trigger this detection, so careful tuning and validation are necessary.

## Attack Chain

1. **Initial Access:** An attacker gains initial access to a system with sufficient privileges to execute PowerShell scripts, possibly through compromised credentials or other initial access vectors (T1078.002).
2. **Discovery:** The attacker uses PowerShell to enumerate existing dMSAs and their associated `msDS-ManagedAccountPrecededByLink` attributes.
3. **Attribute Modification:** The attacker crafts a PowerShell script to modify the `msDS-ManagedAccountPrecededByLink` attribute of a target dMSA. This involves using the `.Put("msDS-ManagedAccountPrecededByLink"` command and specifying a new distinguished name (`CN=`) for the preceding account.
4. **Persistence:** The attacker leverages the modified dMSA link to establish a persistent foothold in the environment by gaining control over the targeted dMSA.
5. **Privilege Escalation:** By manipulating the dMSA links, the attacker effectively inherits the permissions and privileges associated with the compromised dMSA, thereby escalating their own privileges.
6. **Defense Evasion:** The attacker may attempt to evade detection by obfuscating the PowerShell script or using other techniques to hide their activity.
7. **Lateral Movement:** With elevated privileges, the attacker can move laterally within the network, accessing sensitive resources and systems.

## Impact

Successful exploitation of the 'BadSuccessor' vulnerability through modification of the `msDS-ManagedAccountPrecededByLink` attribute can lead to complete domain compromise. An attacker can gain control over critical services and data, potentially resulting in data breaches, service disruptions, and significant financial losses. The impact is amplified in environments heavily reliant on Active Directory for authentication and authorization.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune for your environment to detect potentially malicious modifications to dMSA link attributes via PowerShell (logsource: ps_script, product: windows).
*   Investigate any alerts triggered by the Sigma rule to determine if the activity is legitimate or indicative of an attempted exploitation of the 'BadSuccessor' vulnerability.
*   Implement strict access controls and monitoring for systems and accounts with the ability to modify Active Directory attributes.
*   Review and harden Active Directory security configurations to prevent unauthorized modification of sensitive attributes.
