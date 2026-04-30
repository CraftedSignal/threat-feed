---
title: Office Application Autorun Registry Key Modification
slug: 2024-01-03-office-autorun-registry-modification
description: Adversaries modify Office application autostart extensibility point (ASEP) registry keys to achieve persistence and execute malicious code when Office applications are launched.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - attack.privilege-escalation
  - attack.persistence
  - attack.t1547.001
vendors:
  - Microsoft
products:
  - Microsoft Office
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
  - https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
  - https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d
rules:
  - title: Detect Office Application Addin Registry Modification
    description: Detects modification of Office application add-in registry keys to establish persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Office ClickToRun Registry Modification
    description: Detects modification of Office application add-in registry keys by ClickToRun executables to prevent false positives.
    platform: sigma
    severity: informational
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers may target Microsoft Office applications' autostart extensibility points (ASEPs) in the Windows Registry to establish persistence. By modifying specific registry keys, malicious actors can ensure that their code is executed each time an Office application, such as Word, Excel, or Outlook, is launched. This technique is often employed to maintain a foothold on a compromised system. While legitimate add-ins also leverage these registry keys, unauthorized modifications can lead to the execution of arbitrary code, potentially resulting in data theft, system compromise, or further exploitation. Defenders should be aware that many legitimate applications modify these keys. Thorough testing and tuning is required.

## Attack Chain

1. An attacker gains initial access to the system via an unrelated method.
2. The attacker identifies the relevant Office application ASEP registry keys: `\Software\Wow6432Node\Microsoft\Office`, `\Software\Microsoft\Office` and specific application keys like `\Word\Addins`, `\Excel\Addins`, etc.
3. The attacker modifies the registry key to point to a malicious executable or script. This could be achieved using tools like `reg.exe` or PowerShell.
4. The registry modification ensures that the malicious code is executed upon the next launch of the targeted Office application.
5. The user launches the Office application (e.g., Word, Excel, Outlook).
6. The Office application reads the modified registry key and executes the associated malicious code.
7. The malicious code performs its intended actions, such as downloading additional payloads, establishing command and control, or stealing data.
8. The attacker maintains persistence on the system through the modified registry key, ensuring continued access and control.

## Impact

Successful exploitation allows attackers to achieve persistence on compromised systems. This can lead to data exfiltration, deployment of ransomware, or further lateral movement within the network. The modification of these keys is often performed to maintain a persistent presence, allowing attackers to regain access to the system even after reboots or user logoffs. While the number of direct victims is unknown, the potential for widespread impact is significant, especially in organizations heavily reliant on Microsoft Office applications.

## Recommendation

*   Enable registry modification logging and deploy the provided Sigma rules to your SIEM to detect suspicious changes to Office application autostart registry keys.
*   Regularly audit the Office application add-ins installed on systems to identify and remove any unauthorized or malicious extensions (reference: Sigma rules).
*   Implement application whitelisting to prevent the execution of unauthorized executables and scripts (reference: Attack Chain).
*   Monitor process execution events for Office applications launching unusual or suspicious child processes (reference: Attack Chain).
*   Tune and customize the provided Sigma rules based on your environment's baseline of legitimate Office add-in activity to minimize false positives (reference: Sigma rules).
