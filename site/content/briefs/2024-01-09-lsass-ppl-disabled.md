---
title: LSASS Protection Policy Disabled via Registry Modification
slug: 2024-01-09-lsass-ppl-disabled
description: Attackers may disable Protected Process Light (PPL) protection for the LSASS process by modifying specific registry keys, allowing for credential dumping and other malicious activities.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - defense-evasion
  - lsass
  - ppl
  - registry
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_lsass_ppl_disabled_registry.toml
rules:
  - title: LSASS PPL Disabled via Registry Modification
    description: Detects modification of the ProtectionMode registry key to disable LSASS PPL.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1003.001
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Process creating registry key to disable LSASS PPL
    description: Detects a process creating the registry key related to disable LSASS PPL. Useful to detect if the key did not exist prior to the attack
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1003.001
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers frequently target the LSASS process to extract credentials and other sensitive information. Windows implements Protected Process Light (PPL) as a defense mechanism to prevent unauthorized access to LSASS. This attack involves modifying specific registry keys to disable this protection, potentially occurring post-exploitation. Once PPL is disabled, attackers can more easily dump credentials, inject malicious code, and perform other actions to escalate their privileges and move laterally within the compromised environment. Disabling LSASS protection is a common step in many credential harvesting attack chains.

## Attack Chain

1. The attacker gains initial access to the system (e.g., through phishing or exploiting a vulnerability).
2. The attacker escalates privileges to an administrator or SYSTEM level, often leveraging known exploits or misconfigurations.
3. The attacker modifies the registry key `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ProtectionMode` to a value of `0`, effectively disabling LSASS PPL. This is often done using tools like `reg.exe` or PowerShell.
4. The attacker uses credential dumping tools like `Mimikatz` or custom scripts to extract credentials from the LSASS process memory.
5. The attacker uses the stolen credentials to gain access to other systems or resources within the network (lateral movement).
6. The attacker performs reconnaissance to identify high-value targets and data.
7. The attacker exfiltrates sensitive data or deploys ransomware to achieve their final objective.

## Impact

Disabling LSASS PPL can lead to widespread credential compromise, allowing attackers to gain access to sensitive data and systems within the organization. This can result in significant financial loss, reputational damage, and disruption of business operations. Successful credential dumping can expose domain administrator accounts, effectively giving the attacker complete control over the network. Depending on the scope of access achieved with the compromised credentials, the impact could range from targeted data theft to full-scale ransomware deployment across the network.
