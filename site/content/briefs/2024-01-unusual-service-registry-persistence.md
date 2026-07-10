---
title: Unusual Persistence via Services Registry Modification
slug: 2024-01-unusual-service-registry-persistence
description: Adversaries may modify the Windows services registry keys directly to stealthily persist through abnormal service creation or modification of an existing service, bypassing standard APIs, detected by monitoring registry changes related to service DLLs and image paths.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - registry
  - windows
  - services
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://attack.mitre.org/techniques/T1543/
  - https://attack.mitre.org/techniques/T1574/
  - https://attack.mitre.org/techniques/T1112/
rules:
  - title: Unusual Persistence via Services Registry Modification
    description: Detects processes modifying the services registry key directly, potentially indicating malicious persistence.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1112
      - T1543.003
      - T1574.011
    data_sources:
      - registry_set
      - windows
  - title: Unusual Service Creation via Registry
    description: Detects the creation of a new service via direct registry modification, which can be a sign of malicious persistence.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1112
      - T1543.003
      - T1574.011
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers often seek to establish persistence within a compromised system to maintain unauthorized access. One method involves directly modifying the Windows services registry keys, bypassing standard Windows APIs. This technique allows attackers to create or modify services stealthily, potentially evading detection by traditional security measures. The detection focuses on changes to `ServiceDLL` and `ImagePath` values within the services registry, specifically under `HKLM\SYSTEM\ControlSet*\Services\*`, `\REGISTRY\MACHINE\SYSTEM\ControlSet*\Services\*`, and `MACHINE\SYSTEM\ControlSet*\Services\*`. By monitoring these specific registry paths and filtering out known legitimate processes (e.g., `svchost.exe`, `services.exe`, and processes within `Program Files` or `Windows\System32`), security teams can identify suspicious service modifications indicative of malicious activity. This rule helps detect potential persistence mechanisms and unauthorized system modifications, improving overall security posture.

## Attack Chain

1.  **Initial Compromise:** The attacker gains initial access to the system via an exploit or phishing campaign (details not available in source).
2.  **Privilege Escalation:** The attacker escalates privileges to obtain necessary permissions to modify the registry (details not available in source).
3.  **Identify Target Service:** The attacker identifies a service to modify or creates a new service entry in the registry. The registry path is typically found under `HKLM\SYSTEM\ControlSet*\Services\*`.
4.  **Modify ServiceDLL Value:** The attacker modifies the `ServiceDLL` value in the registry to point to a malicious DLL. This DLL will be loaded when the service starts. Registry path: `HKLM\SYSTEM\ControlSet*\Services\*\ServiceDLL`.
5.  **Modify ImagePath Value:** Alternatively or additionally, the attacker modifies the `ImagePath` value to point to a malicious executable. This executable will be launched when the service starts. Registry path: `HKLM\SYSTEM\ControlSet*\Services\*\ImagePath`.
6.  **Start the Service:** The attacker starts the modified or newly created service, either manually or by triggering an event that causes the service to start automatically.
7.  **Malicious Code Execution:** The malicious DLL or executable specified in the registry key is loaded and executed with elevated privileges.
8.  **Persistence Established:** The attacker maintains persistent access to the system, as the malicious code will execute whenever the service is started.

## Impact

Successful exploitation allows attackers to maintain persistent access to compromised systems, potentially leading to data theft, system compromise, or further lateral movement within the network.  The lack of specific victim numbers or industry targeting in the provided source prevents a more detailed impact assessment.  However, the wide use of Windows services makes this a potentially broad threat.

## Recommendation

*   Enable Windows Registry auditing to capture registry modification events, specifically monitoring the registry paths mentioned in the overview (`HKLM\SYSTEM\ControlSet*\Services\*`, `\REGISTRY\MACHINE\SYSTEM\ControlSet*\Services\*`, `MACHINE\SYSTEM\ControlSet*\Services\*`) (Log Source).
*   Deploy the Sigma rule "Unusual Persistence via Services Registry Modification" to detect unusual modifications to service registry keys, tuning the rule's filters to avoid false positives in your specific environment (Sigma Rule).
*   Investigate and remediate any alerts generated by the Sigma rule, focusing on processes modifying the `ServiceDLL` or `ImagePath` values within the specified registry paths (Sigma Rule).
*   Review and update endpoint protection policies to ensure that unauthorized registry modifications are detected and blocked (Endpoint Protection Policies).
