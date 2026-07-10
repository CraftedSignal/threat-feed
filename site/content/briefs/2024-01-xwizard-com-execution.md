---
title: Execution of COM object via Xwizard
slug: 2024-01-xwizard-com-execution
description: Adversaries can abuse the legitimate system binary Xwizard to execute Component Object Model (COM) objects, evading defensive countermeasures by running COM objects created in the registry.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - defense-evasion
  - windows
  - com
  - xwizard
vendors:
  - Microsoft
products:
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
  - title: Detect Suspicious Xwizard COM Object Execution
    description: Detects the execution of Xwizard with the RunWizard command and a GUID, indicating potential malicious COM object execution.
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
  - title: Detect Unusual Xwizard Location
    description: Detects Xwizard executing from a non-standard directory, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Xwizard is a legitimate Windows system binary that can be abused to execute Component Object Model (COM) objects. This technique allows adversaries to bypass security measures and evade detection by leveraging a trusted system tool. By creating a malicious COM object in the registry and then using Xwizard to execute it, attackers can run arbitrary code. This activity can be difficult to detect because it involves the use of a signed, trusted binary. The scope of targeting is broad, as any Windows system is potentially vulnerable if it has Xwizard installed, which is a default component of Windows.

## Attack Chain

1.  The attacker gains initial access to the target system through an unspecified method (e.g., phishing, exploit).
2.  The attacker creates a malicious COM object and registers it within the Windows Registry. This COM object is designed to execute malicious code when invoked.
3.  The attacker uses Xwizard to execute the newly created malicious COM object using the `RunWizard` command and the COM object's GUID.
4.  Xwizard, a legitimate system binary, launches the specified COM object.
5.  The malicious COM object executes its payload, which could include downloading additional malware, establishing persistence, or performing reconnaissance.
6.  The attacker leverages the executed code to escalate privileges or move laterally within the network.
7.  The attacker uses the compromised system to access sensitive data or perform other malicious activities.
8.  The attacker achieves their objective, which could include data exfiltration or system disruption.

## Impact

Successful exploitation allows attackers to execute arbitrary code on the target system, potentially leading to data theft, system compromise, and further lateral movement within the network. While specific victim numbers are unavailable, the widespread presence of Xwizard on Windows systems makes many organizations vulnerable. If successful, attackers can bypass traditional security measures and gain a foothold within the targeted environment.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious Xwizard COM Object Execution` to your SIEM to detect the execution of Xwizard with the `RunWizard` command and a GUID (rules).
*   Deploy the Sigma rule `Detect Unusual Xwizard Location` to detect Xwizard executing from a non-standard directory (rules).
*   Monitor process creation events for executions of `xwizard.exe` with command-line arguments containing `RunWizard` (rules).
*   Audit and review COM object registrations in the Windows Registry for suspicious or unknown entries (content).
*   Implement application control policies to restrict the execution of Xwizard from non-standard locations (content).
