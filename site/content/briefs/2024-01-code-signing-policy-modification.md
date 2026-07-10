---
title: Code Signing Policy Modification Through Built-in Tools
slug: 2024-01-code-signing-policy-modification
description: Detection of attempts to disable or modify the code signing policy on Windows systems using built-in utilities like bcdedit, potentially allowing attackers to execute unsigned malicious code.
date: "2024-01-23T14:30:00Z"
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
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
references:
  - https://attack.mitre.org/techniques/T1553/
  - https://attack.mitre.org/techniques/T1553/006/
rules:
  - title: Code Signing Policy Modification Through Bcdedit
    description: Detects attempts to modify the code signing policy using bcdedit.exe
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553.006
    data_sources:
      - process_creation
      - windows
  - title: Code Signing Policy Modification Through Bcdedit - Test Signing
    description: Detects attempts to enable test signing using bcdedit.exe
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

This detection identifies attempts to disable or modify the code signing policy on Windows systems using built-in utilities. Code signing is a security feature that ensures program authenticity and integrity. By disabling code signing enforcement, threat actors can execute malicious, unsigned code, potentially leading to system compromise. The rule specifically focuses on the use of `bcdedit.exe` with arguments that disable integrity checks or enable test signing mode. This activity is often indicative of an attacker attempting to subvert trust controls to load and execute unsigned or self-signed malicious drivers or other executables. The targeted systems are Windows endpoints. This activity can be used to load malicious drivers, bypass security controls, and gain persistence on a compromised system.

## Attack Chain

1.  The attacker gains initial access to the target system through an unknown method.
2.  The attacker executes `bcdedit.exe` with arguments to disable Driver Signature Enforcement (DSE). Examples of such arguments include `/set testsigning on`, `/set nointegritychecks on`, or `/set loadoptions DISABLE_INTEGRITY_CHECKS`.
3.  `bcdedit.exe` modifies the Boot Configuration Data (BCD) store to allow unsigned drivers or code to load.
4.  The attacker installs a malicious, unsigned driver.
5.  The system loads the malicious driver due to the modified BCD settings.
6.  The malicious driver executes with elevated privileges.
7.  The attacker leverages the malicious driver to perform further malicious activities, such as injecting code into processes or establishing persistence.
8.  The attacker achieves their final objective, such as data theft, system compromise, or establishing a persistent backdoor.

## Impact

Successful modification of the code signing policy allows attackers to load and execute unsigned or self-signed malicious code. This can lead to complete system compromise, as malicious drivers can operate at the kernel level. The number of victims and sectors targeted is unknown. However, the impact of successful code signing policy modification is high due to the potential for privileged access and persistence.

## Recommendation

*   Deploy the Sigma rule "Code Signing Policy Modification Through Bcdedit" to your SIEM to detect malicious use of `bcdedit.exe`.
*   Enable Sysmon process creation logging to activate the rule above.
*   Investigate any instances of `bcdedit.exe` being used with arguments related to testsigning, nointegritychecks, or loadoptions as defined in the Sigma rule.
*   Regularly audit and monitor driver loading events on endpoints.
*   Enforce strict code signing policies through Group Policy.
