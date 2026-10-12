---
title: Detection of Malicious Compiled HTML Help (CHM) Execution
slug: 2026-10-hh-exe-child-process
description: Detection of the Microsoft HTML Help executable (hh.exe) spawning child processes, which indicates the potential use of malicious Compiled HTML Help (CHM) files to execute arbitrary scripts and bypass security controls.
date: "2026-10-12T17:35:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - living-off-the-land
  - windows-security
  - chm-exploitation
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The following analytic detects the execution of hh.exe (HTML Help) spawning a child process, indicating the use of a Compiled HTML Help (CHM) file to execute Windows script code.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1218/001/
  - https://lolbas-project.github.io/lolbas/Binaries/Hh/
rules:
  - title: Detect HTML Help Spawn Child Process
    description: Detects the execution of hh.exe (HTML Help) spawning a child process, which may indicate the use of a malicious CHM file.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1218.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for hh.exe child processes.
      owner: Detection Engineering
      due: 48h
      evidence: This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where hh.exe is the parent process.
  hunt_leads:
    - lead: Search for historical process creation events where parent_process_name is hh.exe.
      technique_id: T1218.001
      data_needed:
        - Process creation events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: This activity is significant as it may indicate an attempt to execute malicious scripts via CHM files.
---

The Microsoft HTML Help executable (hh.exe) is a legitimate Windows binary used to display CHM files. Attackers frequently abuse this binary to facilitate arbitrary code execution by crafting malicious CHM files that trigger scripts upon being opened. This technique (T1218.001) allows adversaries to bypass security controls by leveraging a signed, trusted system executable. This activity has been associated with various threat actors and malware families, including AgentTesla and APT37, as a reliable delivery vector for initial access or secondary stage payloads. Defenders should monitor for instances where hh.exe spawns child processes, as this behavior is typically absent during standard help documentation viewing.

## Attack Chain

1. An attacker crafts a malicious CHM file containing embedded malicious scripts (e.g., JScript or VBScript).
2. The malicious file is delivered to the target via email attachments, file downloads, or social engineering.
3. The user opens the CHM file, triggering the execution of the Microsoft HTML Help engine (hh.exe).
4. The embedded script within the CHM file executes, invoking system commands or additional scripts.
5. The hh.exe process spawns a child process (e.g., cmd.exe, powershell.exe, or wscript.exe) to perform the malicious action.
6. The spawned child process initiates further malicious activity, such as downloading secondary payloads or performing exfiltration.

## Impact

Successful exploitation of this technique can result in unauthorized code execution on the target Windows system. Attackers leverage this to establish initial access, execute malware, or perform persistence operations. This technique has been documented in diverse campaigns, including those attributed to APT37, and is frequently used to facilitate the deployment of infostealers like AgentTesla.

## Recommendation

* Deploy the Sigma rule below to detect suspicious hh.exe parent-child relationships and tune based on local environmental baselines.
* Ingest process creation telemetry (Sysmon Event ID 1 or Windows Security Event ID 4688) into your SIEM to monitor for this specific parent-child lineage.
* Investigate occurrences where hh.exe initiates command-line interpreters or other suspicious child processes.
* Educate users regarding the risks of opening unsolicited CHM files from untrusted sources.
