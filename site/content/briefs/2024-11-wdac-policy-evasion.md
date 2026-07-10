---
title: WDAC Policy File Creation by Unusual Process
slug: 2024-11-wdac-policy-evasion
description: Adversaries may create Windows Defender Application Control (WDAC) policy files using unusual processes to impair defenses and restrict the execution of security products on compromised systems.
date: "2024-11-02T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wdac
  - defense-evasion
  - windows
vendors:
  - Microsoft
products:
  - Windows Defender Application Control
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/logangoins/Krueger/tree/main
  - https://beierle.win/2024-12-20-Weaponizing-WDAC-Killing-the-Dreams-of-EDR/
rules:
  - title: WDAC Policy File Creation by Unusual Process
    description: Detects the creation of WDAC policy files (.p7b or .cip) by processes other than the expected system binaries.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - windows
  - title: WDAC Policy File Created in Active Directory by Unusual Process
    description: Detects WDAC .cip policy files created under \CodeIntegrity\CiPolicies\Active\, indicating active policy modification.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Attackers are increasingly targeting Windows Defender Application Control (WDAC) as a means to evade detection and restrict security tools. This involves crafting malicious WDAC policies that can block legitimate security software, effectively weakening the system's defenses. This technique is particularly effective because WDAC is a native Windows component, making its exploitation less suspicious than disabling third-party security solutions. The observed behavior involves the creation of WDAC policy files with extensions like `.p7b` and `.cip` in specific directories under `\Windows\System32\CodeIntegrity\`. The process creating these files is often unusual and not a standard system utility like `poqexec.exe`. This activity aims to gain persistence and control over the system by manipulating trust policies. Defenders should monitor for unexpected processes creating or modifying WDAC policies to quickly identify and respond to potential defense evasion attempts.

## Attack Chain

1. The attacker gains initial access to the system, potentially through methods not covered in this specific detection (e.g., phishing or exploiting a vulnerability).
2. The attacker elevates privileges to gain necessary permissions to modify WDAC policies (e.g., using exploits or stolen credentials).
3. The attacker crafts a malicious WDAC policy file designed to block specific security products or system utilities.
4. The attacker uses an unusual process, other than the known good binary `poqexec.exe`, to create a WDAC policy file (e.g., a renamed PowerShell script or a custom executable).
5. The WDAC policy file is written to the `\Windows\System32\CodeIntegrity\` or `\Windows\System32\CodeIntegrity\CiPolicies\Active\` directory with either a `.p7b` or `.cip` extension.
6. The operating system loads the newly created WDAC policy, which restricts the execution of targeted security software.
7. The attacker leverages the weakened security posture to deploy malware or perform other malicious activities without interference from the disabled security tools.
8. The attacker maintains persistence by ensuring the malicious WDAC policy remains active across system reboots.

## Impact

Successful execution of this attack can lead to a significant degradation of the system's security posture. By restricting or disabling security products, the attacker gains a window of opportunity to perform malicious activities undetected. This can include data theft, ransomware deployment, or establishing a persistent foothold within the network. The impact is widespread, as this technique can be employed across various sectors, affecting any organization that relies on Windows systems and has implemented WDAC without proper monitoring.

## Recommendation

*   Monitor file creation events for WDAC policy files (`.p7b`, `.cip`) in the `\Windows\System32\CodeIntegrity\` directory by processes other than `poqexec.exe`. Deploy the "WDAC Policy File by an Unusual Process" Sigma rule to detect this activity.
*   Investigate process execution chains of processes creating WDAC policy files to identify potentially malicious parent processes.
*   Implement stricter WDAC policy enforcement and auditing to prevent unauthorized modifications.
*   Enable Sysmon file creation logging to provide the necessary data for the detection rules.
*   Review and baseline expected WDAC policy modifications to identify deviations from normal activity.
*   Tune the provided Sigma rules to filter out legitimate but unusual WDAC policy creation processes in your environment.
