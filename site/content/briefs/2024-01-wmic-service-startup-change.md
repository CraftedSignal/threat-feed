---
title: Service Startup Type Modification via WMIC
slug: 2024-01-wmic-service-startup-change
description: Adversaries use the Windows Management Instrumentation Command-line (WMIC) utility to modify the startup type of services, setting them to 'Manual' or 'Disabled' to impair defenses or disrupt system operations.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - attack.execution
  - attack.t1047
  - attack.defense-evasion
  - attack.t1562.001
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2016
  - Windows Server 2019
  - Windows Server 2022
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1047
    technique_name: Windows Management Instrumentation
references:
  - https://blog.talosintelligence.com/uncovering-qilin-attack-methods-exposed-through-multiple-cases/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_wmic_service_startup_change.yml
rules:
  - title: WMIC Service Startup Type Change to Manual or Disabled
    description: Detects changes to service startup type to 'disabled' or 'manual' using the WMIC command-line utility.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
      - execution
    techniques:
      - T1047
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: WMIC Service Startup Type Change to Manual or Disabled (CommandLine Contains)
    description: Detects changes to service startup type to 'disabled' or 'manual' using the WMIC command-line utility. This rule uses command line contains instead of endswith for image.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
      - execution
    techniques:
      - T1047
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may leverage WMIC, a legitimate Windows command-line utility, to modify the startup type of services. This tactic is often used to disable security products or critical system services, hindering incident response or creating system instability. By setting services to "Manual" or "Disabled", adversaries ensure that these services do not automatically start upon system boot, achieving persistence or impeding detection. While WMIC is a built-in tool, its use for modifying service startup types is often indicative of malicious activity, especially when performed on security-related services. This activity may be part of a larger attack chain aimed at deploying ransomware, exfiltrating data, or establishing a persistent presence on the compromised system.

## Attack Chain

1. An attacker gains initial access to the target system, potentially through phishing, exploiting a vulnerability, or compromised credentials.
2. The attacker executes `wmic.exe` with specific command-line arguments to interact with Windows services.
3. The `service` alias is invoked within WMIC to target specific services.
4. The `ChangeStartMode` method is used to modify the startup type of the targeted service.
5. The attacker sets the startup type to either `Manual` or `Disabled`, preventing the service from automatically starting on subsequent reboots.
6. If the targeted service is a security product, this action effectively disables the defense mechanism.
7. The attacker proceeds with further malicious activities, such as deploying malware or exfiltrating sensitive data, with reduced resistance.
8. The compromised system experiences degraded security posture and potential operational disruptions.

## Impact

Successful modification of service startup types can severely impact system security and availability. Disabling security software can lead to undetected malware infections and data breaches. Disabling critical system services can cause system instability, data loss, or complete system failure. While the exact number of victims is unknown, this technique is broadly applicable across Windows environments, potentially affecting organizations of any size and in any sector. The impact ranges from minor operational disruptions to significant financial losses due to data breaches and ransomware attacks.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect suspicious `wmic.exe` process creations that attempt to change service startup types.
*   Investigate any instances where `wmic.exe` is used to modify service startup types, especially when the targeted services are related to security or critical system functions.
*   Implement endpoint detection and response (EDR) solutions to provide enhanced visibility into process execution and system modifications.
*   Regularly review and audit service configurations to identify unauthorized changes.
