---
brief_id: brief-2026-10-21-alternate-powershell-hosts
event_id: brief-2026-10-21-alternate-powershell-hosts
revision: 1
activity_at: "2026-10-21T00:48:16Z"
title: Detection of Alternate PowerShell Hosts
slug: 2026-10-alternate-powershell-hosts
description: This brief describes the detection of non-standard applications executing PowerShell code, a technique used to evade security monitoring that relies solely on process-name-based filtering of powershell.exe.
date: "2026-10-21T00:48:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
tags:
  - execution
  - powershell
  - detection-engineering
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.001
    subtechnique_name: PowerShell
    evidence: Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe
    confidence_band: high
rules:
  - title: Detect Alternate PowerShell Hosts
    description: Detects PowerShell module activity initiated by processes other than standard PowerShell interpreters to identify potential bypasses.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - ps_module
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Module Logging (Event ID 4103)
      owner: IT Operations
      due: 48h
      evidence: Required to generate logs for this detection
  hunt_leads:
    - lead: Identify processes other than powershell.exe/pwsh.exe that trigger PowerShell Module events
      technique_id: T1059.001
      data_needed:
        - Event ID 4103
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source notes indicate use of alternate hosts to evade process-based detection
---

Attackers frequently leverage alternative hosts to execute PowerShell scripts as a means to evade detection mechanisms configured to monitor only the standard `powershell.exe` or `pwsh.exe` processes. By embedding the PowerShell engine within custom binaries, signed trusted applications, or living-off-the-land binaries, adversaries can maintain persistence and perform post-exploitation activity while remaining invisible to standard process-creation telemetry focused on known interpreters. This technique involves utilizing the PowerShell managed API to host the runtime in-process, effectively decoupling the execution from the standard command-line wrappers. Defenders must monitor the PowerShell Module logging (Event ID 4103) to identify the "HostName" and "HostApplication" fields, which reveal the actual binary initiating the PowerShell runspace, rather than relying on process-based detection.

## Attack Chain

1. Attacker identifies a legitimate, signed, or obscure binary that supports hosting the .NET runtime.
2. Attacker develops or selects a payload to execute in-memory via the hosted PowerShell engine.
3. Attacker triggers the execution of the target binary with arguments that invoke the PowerShell runspace initialization.
4. The host process initializes the System.Management.Automation assembly to host the PowerShell environment.
5. The PowerShell engine executes the malicious script block or command, which appears as child activity of the host process, not `powershell.exe`.
6. Attacker performs discovery, credential access, or data staging within the context of the host process.
7. Attacker maintains stealth by avoiding spawns of child processes commonly monitored for PowerShell execution.

## Impact

Successful abuse of alternate PowerShell hosts allows attackers to bypass endpoint detection and response (EDR) rules that alert on common PowerShell-related command-line arguments. This increases the attacker's dwell time and operational security, facilitating long-term access, lateral movement, and data exfiltration within target environments.

## Recommendation

- Enable Microsoft-Windows-PowerShell/Operational (Event ID 4103) to capture "HostName" and "HostApplication" metadata.
- Deploy the provided Sigma rule to detect PowerShell code execution initiated by unexpected parent processes.
- Baseline legitimate administrative tools in the environment to minimize false positives, specifically identifying software that uses the PowerShell API (e.g., system management or backup agents).
