---
title: Suspicious Execution of InstallUtil with Suppressed Logging
slug: 2026-09-installutil-stealth
description: Adversaries leverage the native .NET InstallUtil.exe utility with specific flags to execute arbitrary code while bypassing standard logging and console output mechanisms.
date: "2026-09-03T13:46:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - execution
  - evasion
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Uses the .NET InstallUtil.exe application in order to execute image without log.
    confidence_band: high
rules:
  - title: Suspicious Execution of InstallUtil Without Log
    description: Detects the use of InstallUtil.exe with flags intended to suppress logging and console output, a technique often used for stealthy code execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the provided Sigma rule to SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Rule definition in brief.
  hunt_leads:
    - lead: Search for historical process creation events involving InstallUtil.exe with empty /logfile arguments.
      technique_id: T1218
      data_needed:
        - Process creation telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Known technique for stealthy execution.
---

InstallUtil.exe is a command-line tool included with the .NET Framework designed for installing and uninstalling server resources by executing installer components in specified assemblies. Threat actors utilize this utility as a living-off-the-land (LotL) binary to execute arbitrary code. By specifically invoking InstallUtil with the '/logfile=' parameter set to a blank value and '/LogToConsole=false', attackers suppress execution logs and console feedback, making the activity more difficult to track through standard administrative monitoring. This technique has been observed in various campaigns, including persistent threats leveraging sophisticated modular malware components.

## Attack Chain

1. The attacker gains initial access through a separate exploit or phishing payload.
2. The attacker drops a malicious .NET assembly file onto the target file system.
3. The attacker locates the .NET Framework installation directory.
4. The attacker initiates the execution of 'InstallUtil.exe' via 'cmd.exe' or 'powershell.exe'.
5. The attacker passes the '/logfile=' and '/LogToConsole=false' flags to ensure the utility executes the assembly silently.
6. InstallUtil loads the malicious assembly into memory and executes the installer component code.
7. The final objective (e.g., C2 beaconing, payload persistence, or data exfiltration) is achieved via the context of the running InstallUtil process.

## Impact

Successful exploitation allows for the execution of arbitrary, unsigned, or malicious code within the context of a trusted system binary. This technique provides a stealthy mechanism to bypass traditional monitoring, potentially leading to persistent unauthorized access or full system compromise depending on the privileges of the executing user.

## Recommendation

Deploy the provided Sigma rule to detect the specific combination of command-line arguments indicative of logging suppression. Ensure Sysmon Process Creation events (Event ID 1) are enabled and ingested into the SIEM. Prioritize the investigation of any process spawning from 'InstallUtil.exe' that interacts with suspicious network endpoints or unsigned DLLs.
