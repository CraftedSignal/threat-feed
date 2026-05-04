---
title: Xwizard COM Object Execution for Defense Evasion
slug: 2024-01-xwizard-com-execution
description: Adversaries may abuse Xwizard, a Windows system binary, to execute Component Object Model (COM) objects created in the registry to evade defensive countermeasures by proxying execution through a legitimate system tool.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - defense-evasion
  - com-object
  - xwizard
  - windows
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1559
    technique_name: Inter-Process Communication
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Xwizard/
  - http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/
rules:
  - title: Detect Xwizard COM Object Execution via CommandLine
    description: Detects suspicious execution of Xwizard with RunWizard argument, indicating potential COM object execution for evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218
      - T1559.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Xwizard COM Object Execution via Image Location
    description: Detects execution of Xwizard from unusual locations, indicating potential COM object execution for evasion.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218
      - T1559.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Windows Component Object Model (COM) facilitates communication between software components. Attackers can leverage Xwizard, a legitimate Windows system binary, to execute COM objects and bypass security measures. This technique allows adversaries to proxy the execution of malicious code through a trusted system utility, making detection more challenging. This activity has been observed since at least 2017, with potential links to PlugX malware variants. The scope of targeting is broad, as any Windows system with vulnerable COM configurations could be susceptible. Defenders should monitor Xwizard execution for suspicious arguments and deviations from expected file paths to identify potential misuse of COM objects.

## Attack Chain

1.  The attacker gains initial access via an unconfirmed method (e.g., phishing, exploit).
2.  The attacker modifies the Windows Registry to create a malicious COM object.
3.  The attacker invokes `xwizard.exe` with the `RunWizard` argument and a GUID referencing the malicious COM object.
4.  `xwizard.exe` reads the COM object's configuration from the registry.
5.  `xwizard.exe` executes the code associated with the malicious COM object.
6.  The malicious COM object performs unauthorized actions, such as downloading additional payloads or establishing command and control.
7.  The attacker achieves persistence by ensuring the malicious COM object is executed on system startup or user login.
8.  The attacker executes arbitrary code, potentially leading to data theft or system compromise.

## Impact

Successful exploitation allows attackers to execute arbitrary code on compromised systems. This can lead to data theft, malware installation, or complete system compromise. The targeted sectors are broad, as any Windows system with vulnerable COM configurations is susceptible. While specific victim counts are unavailable, the widespread use of Windows makes this a potentially significant threat. If the attack succeeds, attackers can gain persistent access, escalate privileges, and move laterally within the network.

## Recommendation

*   Monitor process execution events for instances of `xwizard.exe` with suspicious arguments like `RunWizard` and GUIDs using the "Execution of COM object via Xwizard" rule as a baseline.
*   Implement the Sigma rules provided to detect anomalous Xwizard executions and COM object abuse.
*   Audit and monitor registry modifications, specifically looking for COM object registrations using registry_set rules.
*   Ensure that endpoint detection and response (EDR) solutions are configured to detect and block suspicious process executions originating from `xwizard.exe`.
*   Enable Sysmon process creation logging (Event ID 1) and registry event logging (Event ID 12, 13, 14) for enhanced visibility, as mentioned in the setup guide.
