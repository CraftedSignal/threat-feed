---
title: Indirect Command Execution via forfiles.exe
slug: 2026-10-windows-forfiles-abuse
description: The Windows 'forfiles.exe' utility can be abused by attackers to execute arbitrary commands as a proxy, enabling evasion of command-line monitoring and facilitating post-exploitation activity.
date: "2026-10-12T18:08:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - defense-evasion
  - windows
  - endpoint-security
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: The detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where forfiles.exe is the parent process.
    confidence_band: high
rules:
  - title: Detect Indirect Command Execution via forfiles.exe
    description: Detects the use of forfiles.exe with the /c argument to execute a child process, which may indicate indirect command execution used for evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to environment
      owner: Detection Engineering
      due: 48h
      evidence: Source document identifies forfiles.exe as a common evasion technique
  hunt_leads:
    - lead: Search for processes spawned by forfiles.exe
      technique_id: T1202
      data_needed:
        - Process creation events
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Analytic provided by Splunk for hunting forfiles abuse
  mitigation_plan:
    - priority: medium_term
      action: Restrict execution of administrative tools to authorized service accounts
      owner: IT Operations
      addresses: T1202
      evidence: General security best practice for living-off-the-land techniques
---

The Windows utility 'forfiles.exe' is a legitimate system tool designed to select files in a directory and run a command on each file. However, threat actors leverage this functionality for indirect command execution to bypass security controls that monitor for direct process launches or suspicious command-line patterns. By utilizing the '/c' flag, an attacker can specify a custom command string that forfiles.exe executes on behalf of the attacker, effectively masking the true origin of the malicious process. This technique is frequently observed in post-exploitation scenarios where adversaries maintain persistence or perform lateral movement while attempting to evade detection by security software. Defenders must identify process creation events where forfiles.exe acts as the parent, particularly when the command line includes the '/c' switch, as this is a hallmark of indirect execution.

## Impact

Successful abuse of forfiles.exe allows an attacker to execute arbitrary code with the permissions of the user or system account running the utility. This can lead to full system compromise, unauthorized data exfiltration, or the deployment of additional malicious payloads. While common in 'living off the land' post-exploitation activity, this technique remains a significant risk for environments where command-line telemetry is the primary defense against scripting-based attacks.

## Recommendation

Prioritize the implementation of process creation monitoring to identify potential abuse of system utilities.

- Deploy the Sigma rule below to detect suspicious parent-child relationships involving forfiles.exe.
- Establish a baseline for legitimate administrative usage of forfiles.exe within the environment to reduce false positives.
- Enable Sysmon or EDR process creation logging to capture parent-child process relationships and command-line arguments.
- Investigate any forfiles.exe processes that execute unexpected binaries, especially those originating from unexpected parent processes or locations.
