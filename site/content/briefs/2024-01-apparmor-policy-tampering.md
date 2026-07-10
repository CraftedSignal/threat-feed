---
title: AppArmor Policy Interface Tampering
slug: 2024-01-apparmor-policy-tampering
description: Detection of unauthorized access to AppArmor kernel policy control interfaces, specifically the `.load`, `.replace`, or `.remove` files, indicating potential defense evasion or policy tampering on Linux systems.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - apparmor
  - defense-evasion
  - linux
vendors:
  - Linux
products:
  - AppArmor
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_apparmor_policy_access.toml
  - https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt
  - https://blog.qualys.com/vulnerabilities-threat-research/2026/03/12/crackarmor-critical-apparmor-flaws-enable-local-privilege-escalation-to-root
rules:
  - title: AppArmor Policy Load/Replace/Remove Activity
    description: Detects the use of file operations to load, replace, or remove AppArmor profiles, which can indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
  - title: AppArmor Policy Modification via Command Line
    description: Detects command-line arguments indicative of AppArmor policy loading or replacement.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
  - title: Auditd Manager AppArmor Configuration File Changes
    description: Detects writes to the Auditd Manager configuration file to modify the AppArmor auditing rules.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
rules_count: 3
---

This threat brief focuses on detecting attempts to tamper with AppArmor policies on Linux systems. AppArmor is a security module that provides mandatory access control, limiting the actions that processes can take. Attackers may try to modify or disable AppArmor policies to evade detection and execute malicious code with fewer restrictions. This is achieved by directly interacting with the AppArmor kernel policy control interfaces, specifically the `.load`, `.replace`, and `.remove` files located under `/sys/kernel/security/apparmor/`. These files are used to load, modify, or remove AppArmor profiles. The rule published on 2026-03-23 identifies abnormal access to these interfaces which could indicate unauthorized policy changes, defense evasion, or the installation of attacker-controlled profiles. This type of activity is particularly concerning in environments where AppArmor policy changes are uncommon or strictly controlled.

## Attack Chain

1. **Initial Access:** The attacker gains initial access to the system, potentially through exploiting a vulnerability or using compromised credentials.
2. **Privilege Escalation:** The attacker escalates privileges to root or another account with sufficient permissions to modify AppArmor policies. This may involve exploiting a kernel vulnerability or misconfigured sudo permissions.
3. **Defense Evasion:** The attacker attempts to modify or disable AppArmor policies to evade detection and allow the execution of malicious code.
4. **Policy Modification:** The attacker writes to `/sys/kernel/security/apparmor/.load`, `/sys/kernel/security/apparmor/.replace`, or `/sys/kernel/security/apparmor/.remove` to load a malicious AppArmor profile, replace an existing one with a weakened version, or remove a profile entirely.
5. **Persistence:** The attacker establishes persistence by creating or modifying systemd units, cron jobs, or startup scripts that execute malicious code after the AppArmor policy is altered.
6. **Malicious Code Execution:** The attacker executes malicious code that was previously blocked by AppArmor policies, now allowed due to the modified policies.
7. **Lateral Movement/Data Exfiltration:** The attacker moves laterally within the network, accessing sensitive data or systems, and exfiltrates data to an external location.
8. **Impact:** The attacker achieves their final objective, which may include data theft, system compromise, or disruption of services.

## Impact

Successful tampering with AppArmor policies can have severe consequences. Attackers can bypass security controls, install malicious software, and gain unauthorized access to sensitive data. This can lead to data breaches, financial losses, and reputational damage. The impact is amplified if the compromised system is critical to business operations or contains valuable data. The referenced Qualys advisory "CrackArmor" highlights critical AppArmor flaws enabling local privilege escalation to root, further emphasizing the potential damage.

## Recommendation

*   Deploy the provided EQL rule to your SIEM to detect access to AppArmor policy interfaces and tune it for your specific environment.
*   Enable the `auditd_manager` integration and configure the recommended audit rules to monitor access to the AppArmor policy files: `-w /sys/kernel/security/apparmor/.load -p rw -k apparmor_policy_change`, `-w /sys/kernel/security/apparmor/.replace -p rw -k apparmor_policy_change`, `-w /sys/kernel/security/apparmor/.remove -p rw -k apparmor_policy_change`.
*   Regularly review AppArmor policies for unauthorized modifications and ensure that critical services are running with the expected policies.
*   Implement strict access controls to limit who can administer AppArmor policies.
*   Monitor for privilege escalation attempts and unauthorized use of `sudo`.
