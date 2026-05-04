---
title: Suspicious Process Creation Followed by Memory Access from Unknown Region
slug: 2024-01-suspicious-process-calltrace
description: The rule identifies suspicious process creation where a process is created and immediately accessed from an unknown memory code region by the same parent process, indicating a potential code injection attempt, specifically process hollowing, commonly targeting processes spawned by Microsoft Office applications, scripting engines, and command-line tools for defense evasion.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - process-injection
  - windows
vendors:
  - Microsoft
  - Adobe
products:
  - Office
  - EdgeWebView
  - Acrobat DC
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_suspicious_process_creation_calltrace.toml
  - https://attack.mitre.org/techniques/T1055/
  - https://attack.mitre.org/techniques/T1055/012/
rules:
  - title: Suspicious Process Creation CallTrace - Sigma
    description: Detects process creation followed by memory access from an unknown region, potentially indicating code injection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1055
      - T1055.012
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Creation via Office Apps with Unknown CallTrace
    description: Detects process creation by MS Office applications immediately followed by process access event from unknown module.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1055
      - T1055.012
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies potential process injection attempts, specifically process hollowing, by monitoring process creation events followed by memory access from unknown regions. The rule focuses on processes spawned by Microsoft Office applications (winword.exe, excel.exe, outlook.exe, powerpnt.exe), scripting engines (cscript.exe, wscript.exe, mshta.exe), and command-line tools (cmd.exe, powershell.exe, rundll32.exe, regsvr32.exe, wmic.exe, cmstp.exe, msxsl.exe). The logic looks for a spawned process by one of these applications/tools, followed by a process access event for an unknown memory region by the parent process, indicating a potential code injection attempt. Attackers use process injection to hide malicious activity within legitimate processes, evading detection and hindering forensic analysis. This technique is a common tactic used to establish persistence, escalate privileges, or execute malicious payloads.

## Attack Chain

1. A user opens a malicious document or executes a script.
2. The Microsoft Office application (e.g., winword.exe) or scripting engine (e.g., wscript.exe) starts as a parent process.
3. The parent process creates a new child process (e.g., a legitimate system executable).
4. The attacker injects malicious code into the newly created child process's memory, often overwriting legitimate code sections.
5. The parent process accesses the child process's memory from an unknown code region, indicating the injected code. Sysmon event ID 10 captures this access.
6. The injected code executes within the context of the child process, performing malicious actions.
7. These actions can include establishing persistence, downloading additional malware, or exfiltrating data.

## Impact

Successful process injection allows attackers to mask their malicious activities within legitimate processes, making detection and attribution significantly harder. This can lead to prolonged infections, data breaches, and system compromise. The impact can range from individual workstation compromise to widespread organizational damage, depending on the attacker's objectives and the compromised system's role. The rule mitigates risks associated with advanced persistent threats (APTs) and commodity malware using process injection for defense evasion.

## Recommendation

*   Enable Sysmon Event ID 1 (Process Creation) and Event ID 10 (Process Access) to collect the necessary telemetry for this detection ([Sysmon Event ID 1 - Process Creation](https://ela.st/sysmon-event-1-setup), [Sysmon Event ID 10 - Process Access](https://ela.st/sysmon-event-10-setup)).
*   Deploy the Sigma rule "Suspicious Process Creation CallTrace" to your SIEM and tune for your environment.
*   Investigate any alerts triggered by the Sigma rule, focusing on the process execution chain and potential malicious activities performed by the injected code.
*   Consider memory dumping the child process for further analysis, to examine if malicious code exists.
