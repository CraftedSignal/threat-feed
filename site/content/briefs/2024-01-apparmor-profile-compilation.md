---
title: AppArmor Profile Compilation via apparmor_parser
slug: 2024-01-apparmor-profile-compilation
description: Adversaries may abuse `apparmor_parser` to compile custom AppArmor profiles, potentially weakening security controls and facilitating privilege escalation on Linux systems.
date: "2024-01-03T12:00:00Z"
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
  - https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt
  - https://blog.qualys.com/vulnerabilities-threat-research/2026/03/12/crackarmor-critical-apparmor-flaws-enable-local-privilege-escalation-to-root
rules:
  - title: AppArmor Profile Compilation via apparmor_parser
    description: Detects the execution of `apparmor_parser` with arguments used to specify an output file, which may indicate malicious profile compilation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
  - title: AppArmor Policy Load via apparmor_status
    description: Detects the usage of apparmor_status to load or reload apparmor policies, which can follow malicious compilation
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `apparmor_parser` tool is used to compile AppArmor profiles on Linux systems. While typically used by system administrators and package installation scripts, adversaries can abuse this tool to compile malicious AppArmor profiles. These profiles can then be loaded into the kernel, potentially weakening security controls, altering the behavior of privileged programs, or assisting in exploitation chains. Detecting the use of `apparmor_parser` with output redirection flags such as `-o` is crucial for identifying potential attempts to manipulate AppArmor policies for malicious purposes. This activity is a component of defense evasion, enabling attackers to potentially disable security tools.

## Attack Chain

1. An attacker gains initial access to a Linux system, often through methods outside the scope of this specific detection (e.g., exploiting a vulnerability, compromised credentials).
2. The attacker escalates privileges to root, which is typically required to modify or load AppArmor profiles.
3. The attacker creates a malicious AppArmor profile. This profile might weaken restrictions on specific processes or grant excessive permissions.
4. The attacker executes `apparmor_parser` with the `-o` option (or similar variants) to compile the malicious AppArmor profile to a file.
5. The attacker loads the compiled profile into the AppArmor kernel module using tools like `apparmor_status` or other policy management interfaces, replacing an existing policy or adding a new one.
6. The attacker restarts the service targeted by the malicious AppArmor profile, or triggers a reload of AppArmor policies, to activate the new profile.
7. The attacker leverages the weakened security controls to execute malicious code, escalate privileges further, or maintain persistence.
8. The attacker achieves their final objective, such as data exfiltration, system compromise, or denial of service.

## Impact

A successful attack using a maliciously compiled AppArmor profile can lead to significant compromise of a Linux system. Weakening AppArmor policies can allow attackers to bypass security restrictions, escalate privileges, and execute arbitrary code with elevated permissions. This can result in data breaches, system instability, or complete system takeover. The impact is amplified if critical services like `sshd`, `sudo`, or container runtimes are targeted.

## Recommendation

*   Implement the Sigma rule `AppArmor Profile Compilation via apparmor_parser` to detect the execution of `apparmor_parser` with output options.
*   Enable process monitoring and audit logging on Linux systems to capture command-line arguments for process executions.
*   Monitor for modifications to AppArmor policy directories (e.g., `/etc/apparmor.d/`) and policy loading events.
*   Implement strict access controls on AppArmor policy files and restrict who can load or modify policies.
*   Investigate any unexpected executions of `apparmor_parser` or modifications to AppArmor policies, especially when originating from unknown or untrusted sources.
