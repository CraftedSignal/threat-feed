---
title: Detection of Renamed Windows Command Interpreters
slug: 2026-10-renamed-windows-interpreter
description: Adversaries attempt to evade security controls by renaming standard Windows command interpreters like cmd.exe or powershell.exe to masquerade as benign files.
date: "2026-10-05T18:01:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
  - living-off-the-land
  - masquerading
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Processes that have been renamed and executed may be an indicator that an adversary is attempting to evade defenses or execute malicious code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The following analytic identifies a Windows command interpreter process being executed where it's process name does not match it's original file name attribute.
    confidence_band: high
rules:
  - title: Detect Renamed Windows Command Interpreter
    description: Detects execution of Windows command interpreters where the process name does not match the original file name metadata, a sign of masquerading.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to identify renamed command interpreters
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for renamed process detection
  hunt_leads:
    - lead: Search for processes executing from non-standard paths where OriginalFileName matches known system binaries
      technique_id: T1036.003
      data_needed:
        - Sysmon EID 1 or equivalent process execution logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Renamed binaries often reside in writable directories like AppData or ProgramData
---

Adversaries frequently employ masquerading techniques to evade endpoint security defenses. A common tactic involves renaming legitimate Windows system utilities, such as command interpreters (cmd.exe, powershell.exe), to mimic other benign applications. This activity is designed to bypass security products that rely on process name allowlisting or signature-based detection. Defenders can identify this activity by comparing the executing process name against the internal 'OriginalFileName' attribute embedded within the executable metadata. Discrepancies between these two fields, where a known system binary is executed under an alias, often indicate malicious activity associated with Living Off the Land (LotL) techniques. This detection methodology is applicable to Windows environments leveraging EDR telemetry to monitor process creation events.

## Attack Chain

1. Attacker gains initial access or code execution on a Windows endpoint.
2. Attacker locates standard command interpreter binaries such as C:\Windows\System32\cmd.exe.
3. Attacker copies or moves the binary to a different file path or renames it to a deceptive name (e.g., C:\ProgramData\svchost.exe or update.exe).
4. Attacker executes the renamed binary to maintain process execution while blending in with legitimate system processes.
5. Attacker executes scripts or commands via the renamed interpreter to perform lateral movement or data exfiltration.
6. Security controls failing to perform deep metadata inspection allow the execution, as the process name matches an ignored or trusted pattern.

## Impact

Successful execution of renamed system utilities allows attackers to persist within the environment, evade detection, and execute arbitrary code. This can lead to unauthorized data access, intellectual property theft, and potential system compromise across the affected Windows environment.

## Recommendation

1. Enable Sysmon Event ID 1 (Process Creation) to capture 'OriginalFileName' and 'ProcessName' fields for all process executions.
2. Implement the provided Sigma rule to flag instances where the process name does not match the internal original file name for common Windows interpreters.
3. Tune the detection by creating an allowlist for known third-party binaries that may legitimately share names with system utilities.
4. Hunt for anomalous process execution paths that deviate from standard Windows system directories (e.g., C:\Windows\System32).
