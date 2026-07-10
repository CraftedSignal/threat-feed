---
title: Conhost Spawned By Suspicious Parent Process
slug: 2024-01-conhost-suspicious-parent
description: The Windows Console Host process (conhost.exe) spawned by a suspicious parent process, such as lsass.exe or explorer.exe, can indicate code injection used to bypass application allowlisting and execute malicious commands.
date: "2024-01-09T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - execution
  - defense-evasion
  - privilege-escalation
  - process-injection
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1055
    technique_name: Process Injection
references:
  - https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-one.html
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1036/
  - https://attack.mitre.org/techniques/T1055/
  - https://attack.mitre.org/tactics/TA0002/
  - https://attack.mitre.org/tactics/TA0005/
  - https://attack.mitre.org/tactics/TA0004/
rules:
  - title: Conhost Spawned By Suspicious Parent Process
    description: Detects when conhost.exe is spawned by a suspicious parent process, which could indicate code injection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
      - privilege_escalation
    techniques:
      - T1036
      - T1055
      - T1059
    data_sources:
      - process_creation
      - windows
  - title: Conhost Tampering Check via Process Name
    description: Detects suspicious process creations with conhost process name but from a non-standard path.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers frequently inject custom shell implementations into legitimate system processes to evade detection, bypass application allowlisting, and avoid using command interpreters like cmd.exe or PowerShell.exe. This technique involves spawning `conhost.exe` from unusual parent processes such as `lsass.exe`, `services.exe`, or `explorer.exe`. This behavior contrasts with typical scenarios where `conhost.exe` is initiated by legitimate command-line interfaces or applications. Monitoring process relationships for unusual parent-child connections is essential for identifying potential code injection attempts and malicious activities on Windows systems. This activity is considered high risk due to the potential for privilege escalation and defense evasion, allowing attackers to perform unauthorized actions with elevated privileges. The original Elastic detection rule was created on 2020/08/17 and updated on 2026/04/07.

## Attack Chain

1. An attacker gains initial access to a Windows system through exploitation or social engineering.
2. The attacker injects malicious code into a legitimate system process such as `lsass.exe`, `services.exe`, or `explorer.exe` (Process Injection - T1055).
3. The injected code executes within the context of the compromised process.
4. The compromised process spawns `conhost.exe`, the Console Window Host (Execution via Command and Scripting Interpreter - T1059).
5. The spawned `conhost.exe` instance is used to execute arbitrary commands without typical auditing or security controls.
6. The attacker uses `conhost.exe` to perform reconnaissance, move laterally, or achieve persistence.
7. The attacker escalates privileges by leveraging the compromised process's elevated permissions (Privilege Escalation - TA0004).
8. The attacker achieves their final objective, such as data exfiltration, system compromise, or deploying ransomware.

## Impact

Successful exploitation leads to arbitrary code execution within a legitimate system process, enabling attackers to perform malicious activities, escalate privileges, and evade detection. This can result in data theft, system compromise, and disruption of services. The masquerading of malicious activity within a trusted process makes detection challenging, potentially affecting numerous systems across an organization. If successful, attackers can bypass standard security measures and maintain a persistent presence on compromised systems.

## Recommendation

*   Deploy the Sigma rule "Conhost Spawned By Suspicious Parent Process" to your SIEM and tune for your environment to detect this specific parent/child process relationship.
*   Investigate any instances of `conhost.exe` spawned by parent processes like `lsass.exe`, `services.exe`, or `explorer.exe` to determine legitimacy.
*   Enable Sysmon process-creation logging to provide the necessary data for the Sigma rules above.
*   Review and harden process whitelisting policies to prevent execution of unauthorized code.
