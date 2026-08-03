---
title: Suspicious Cross-User Process Spawning Behavior
slug: 2026-08-cross-user-spawn
description: Detection of common user-space applications being spawned under different user contexts, which often indicates privilege escalation testing or sacrificial process execution.
date: "2026-08-03T08:54:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - stealth
  - windows
  - process-creation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1055
    technique_name: Process Injection
    evidence: Processes such as notepad.exe, calculator etc. are often targeted as sacrificial process or decoy process to check successful privilege escalation.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1134
    technique_name: Access Token Manipulation
    evidence: Detects suspicious spawning of a process under a different user context than the parent process.
    confidence_band: high
rules:
  - title: Detect Suspicious Cross-User Process Spawn
    description: Detects spawning of common desktop applications under a different user context than the parent, often indicative of privilege escalation testing.
    platform: sigma
    severity: medium
    tactics:
      - privilege-escalation
    techniques:
      - T1055
      - T1134
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for unusual process/user pairings.
      owner: Detection Engineering
      due: 72h
      evidence: Source rule definition.
  hunt_leads:
    - lead: Search for processes (notepad, calc) where User != ParentUser
      technique_id: T1055
      data_needed:
        - Process creation logs with User and ParentUser context
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Sigma rule logic.
---

This brief details the detection of suspicious process spawning behavior where applications typically associated with a standard user session - such as notepad.exe, calc.exe, or mspaint.exe - are launched under a different user context than their parent process. Attackers often utilize these binaries as sacrificial or decoy processes to verify the success of privilege escalation attempts or to host injected code. Because these applications are inherently designed for interactive user tasks, a disparity between the parent process user and the spawned child process user is a high-fidelity indicator of potential post-exploitation activity or lateral movement within a Windows environment.

## Impact

Successful execution of such techniques allows attackers to validate elevated privileges, bypass user-mode access controls, and hide malicious code within seemingly benign, commonly running processes. If left undetected, this activity provides a mechanism for persistence and privilege escalation, potentially leading to unauthorized access to sensitive data or elevated control over the affected system.

## Recommendation

Deploy the provided Sigma rule to detect unexpected user context switching for common Windows desktop applications. Monitor and tune the alerts to account for legitimate administrative tasks utilizing 'RunAs' or similar service account management tools. Ensure that process creation logging with full command line arguments and user context metadata is enabled via Sysmon (Event ID 1) or Windows Security Event Logs (Event ID 4688).
