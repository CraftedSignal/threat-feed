---
title: Abuse of PowerShell Disable-WindowsOptionalFeature for Defense Impairment
slug: 2026-09-disable-windows-optional-feature
description: Adversaries leverage the Disable-WindowsOptionalFeature PowerShell cmdlet to disable security features like Windows Defender, facilitating defense impairment and persistence.
date: "2026-09-01T12:08:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-impairment
  - powershell
  - windows-security
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: The cmdlet is used to enumerate, install, uninstall, configure, and update features and packages in Windows images.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_disable_windows_optional_feature.yml
  - https://learn.microsoft.com/en-us/powershell/module/dism/disable-windowsoptionalfeature?view=windowsserver2022-ps
rules:
  - title: Detect Disable-WindowsOptionalFeature for Security Features
    description: Detects the use of the Disable-WindowsOptionalFeature PowerShell cmdlet to disable Windows Defender components, indicating potential defense impairment.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints
      owner: IT Operations
      due: 48h
      evidence: Required for robust detection of cmdlets
  hunt_leads:
    - lead: Search for historical logs of Disable-WindowsOptionalFeature usage
      technique_id: T1562.001
      data_needed:
        - Event ID 4104
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The technique is known for being used to disable security features
  mitigation_plan:
    - priority: medium
      action: Implement GPO to restrict administrative modification of Windows security features
      owner: IT Operations
      addresses: Defense impairment via DISM
      evidence: Limiting administrative rights reduces the risk of this TTP
---

The Disable-WindowsOptionalFeature PowerShell cmdlet, a native component of the Deployment Image Servicing and Management (DISM) toolset, is increasingly targeted by adversaries to disable critical Windows security features. By invoking this cmdlet with the -Online and -FeatureName parameters, attackers can programmatically remove or disable built-in services, specifically targeting Windows Defender GUI, features, and application guard components. This technique is part of a broader class of defense impairment where attackers modify system state to reduce visibility or eliminate protective software. As a legitimate administrative function, its misuse often blends with standard system maintenance, making detection dependent on monitoring PowerShell Script Block Logging (Event ID 4104) for specific cmdlet signatures combined with sensitive feature names.

## Attack Chain

1. Initial access is established through a compromised account or social engineering.
2. The attacker gains execution privileges as an administrator, which is required to modify system features.
3. The attacker identifies the target security feature to be disabled (e.g., Windows-Defender).
4. PowerShell is invoked to execute the Disable-WindowsOptionalFeature cmdlet.
5. The -Online parameter is used to target the currently running operating system instance.
6. The -FeatureName parameter specifies the security component to be disabled.
7. The system process modifications are processed by the DISM subsystem.
8. Final objective of defense impairment is achieved, allowing for subsequent malicious activities without detection by local security software.

## Impact

Successful exploitation of this technique results in the complete or partial disabling of built-in Windows security mechanisms. This increases the exposure of the host to further malicious activities, as security tooling (like Windows Defender) is rendered inactive, facilitating long-term persistence and unauthorized data exfiltration.

## Recommendation

Detection engineers should prioritize the visibility of administrative command-line execution and PowerShell script usage.
- Enable PowerShell Script Block Logging (Event ID 4104) to capture the full command syntax.
- Deploy the provided Sigma rule to monitor for suspicious disabling of security-related feature names.
- Audit administrative access policies to ensure that only authorized personnel can execute modification cmdlets.
