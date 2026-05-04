---
title: Code Signing Policy Modification Through Built-in Tools
slug: 2024-01-09-code-signing-policy-modification
description: Attackers may attempt to disable or modify code signing policies on Windows systems by using built-in tools like bcdedit.exe in order to execute unsigned or self-signed malicious code.
date: "2026-05-04T14:17:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - code-signing
  - windows
vendors:
  - Microsoft
  - SentinelOne
  - Crowdstrike
products:
  - M365 Defender
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
references:
  - https://attack.mitre.org/techniques/T1553/
  - https://attack.mitre.org/techniques/T1553/006/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_code_signing_policy_modification_builtin_tools.toml
rules:
  - title: Code Signing Policy Modification Through Bcdedit
    description: Detects attempts to modify code signing policy using bcdedit.exe
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553.006
    data_sources:
      - process_creation
      - windows
  - title: Code Signing Policy Modification Through Bcdedit - Original File Name
    description: Detects attempts to modify code signing policy using bcdedit.exe based on the original file name.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553.006
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may attempt to subvert trust controls by disabling or modifying the code signing policy. This allows them to execute unsigned or self-signed malicious code. This can be achieved by modifying boot configuration data (BCD) settings using the built-in bcdedit.exe utility on Windows. Disabling Driver Signature Enforcement (DSE) allows the loading of untrusted drivers, which can compromise system integrity. The rule identifies commands that can disable the Driver Signature Enforcement feature. The scope of the targeting is broad, as it can affect any Windows system where an attacker gains sufficient privileges to modify the BCD settings. This activity is detected by analyzing process execution events for specific command-line arguments used with bcdedit.exe. The detection rule was last updated on 2026-05-04.

## Attack Chain

1. The attacker gains administrative privileges on a Windows system.
2. The attacker executes `bcdedit.exe` with arguments to disable driver signature enforcement. Example: `bcdedit.exe /set testsigning on` or `bcdedit.exe /set nointegritychecks on`.
3. The `bcdedit.exe` modifies the Boot Configuration Data (BCD) store.
4. The system is restarted to apply the changes made to the BCD.
5. The attacker loads an unsigned or self-signed malicious driver.
6. The malicious driver executes with kernel-level privileges.
7. The attacker performs malicious activities such as installing rootkits, bypassing security controls, or stealing sensitive data.
8. The attacker maintains persistence by ensuring the malicious driver is loaded on subsequent system reboots.

## Impact

Successful modification of the code signing policy can lead to the execution of unsigned or self-signed malicious code, which can compromise the integrity and security of the system. Attackers can install rootkits, bypass security controls, or steal sensitive data. The impact can range from individual system compromise to broader network-wide attacks, depending on the attacker's objectives.

## Recommendation

*   Deploy the Sigma rule "Code Signing Policy Modification Through Built-in Tools" to your SIEM to detect the execution of `bcdedit.exe` with arguments used to disable code signing (process.args).
*   Enable process creation logging with command line arguments on Windows systems to ensure the Sigma rule can capture the relevant events (logsource).
*   Investigate any detected instances of code signing policy modification, as this activity is typically not legitimate and can indicate malicious activity. The rule `First Time Seen Driver Loaded - df0fd41e-5590-4965-ad5e-cd079ec22fa9` can be used to detect suspicious drivers loaded into the system after the command was executed.
*   Ensure that Driver Signature Enforcement is enabled on all systems.
