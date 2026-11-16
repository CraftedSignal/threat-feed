---
brief_id: brief-2026-11-16-windows-cmd-evasive-patterns
event_id: brief-2026-11-16-windows-cmd-evasive-patterns
revision: 1
activity_at: "2026-11-16T21:28:17Z"
title: 'Windows CMD: Evasive command patterns and self-deletion techniques'
slug: 2026-11-windows-cmd-evasive-patterns
description: Attackers leverage built-in cmd.exe features, such as 'call' for command obfuscation and 'timeout' combined with 'del' for self-deletion, to evade detection and hide forensic artifacts during malicious loader or ClickFix social engineering execution.
date: "2026-11-16T21:28:17Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
tags:
  - defense-evasion
  - execution
  - windows
  - cmd
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027.010
    technique_name: Command Obfuscation
    evidence: Adversaries abuse native cmd.exe features such as call combined with variable assignment to assemble commands piece by piece, hiding the real payload from static inspection and string-based detections.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070.004
    technique_name: File Deletion
    evidence: They also chain native utilities such as timeout and del to erase the dropped executable shortly after it has run, which removes evidence and complicates forensic analysis.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: The following analytic detects cmd.exe being used to evade defenses with nothing but built-in commands, a pattern frequently seen in ClickFix-style social engineering and malware loader activity.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1027/010/
  - https://attack.mitre.org/techniques/T1070/004/
  - https://attack.mitre.org/techniques/T1059/003/
  - https://www.huntress.com/blog/clickfix-castleloader-backgroundfix
  - https://www.esentire.com/blog/amatera-stealer-4-0-2-beta-whats-new-in-this-variant
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_cmd_evasive_patterns_through_native_commands.yml
rules:
  - title: Detect Evasive cmd.exe Patterns
    description: Detects cmd.exe being used to obfuscate commands via 'call' with variable assignment or to self-delete payloads via 'timeout' and 'del'
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027.010
      - T1059.003
      - T1070.004
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
    - action: Deploy the provided Sigma rule to detect suspicious cmd.exe command-line patterns
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command line patterns used by malicious loaders
  hunt_leads:
    - lead: Search for non-SYSTEM user cmd.exe executions containing 'call' combined with variable assignment, or 'timeout' and 'del' chains
      technique_id: T1027.010
      data_needed:
        - Endpoint process creation logs
        - Command line string
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: The analytic monitors Sysmon and Windows Security event logs for these specific command patterns, excluding SYSTEM-level executions to reduce noise.
---

## Overview

Malware loaders and ClickFix-style social engineering campaigns frequently abuse native Windows CMD functionality to perform malicious operations while avoiding detection. Adversaries utilize the 'call' command alongside variable assignment to construct commands dynamically, effectively hiding the actual payload from static string-based analysis. Furthermore, after execution, attackers often chain the 'timeout' and 'del' commands to automatically remove the dropped malicious executable. This cleanup behavior deletes forensic evidence from the host, complicating post-incident analysis.

## Attack Chain

1. Initial Access: User is lured via social engineering (e.g., ClickFix campaigns) to execute a malicious script or batch file.
2. Command Obfuscation: The script uses 'cmd.exe' with 'call' and variable assignment to deobfuscate and assemble the final payload at runtime.
3. Execution: The payload executes, potentially dropping an additional malicious binary.
4. Persistence/Cleanup Preparation: The script schedules a delay using the 'timeout' command.
5. Evidence Removal: The 'del' command is triggered to delete the original script or the dropped binary.
6. Forensic Evasion: The command shell exits, leaving minimal evidence of the primary payload on the system.

## Recommendation

- Deploy detection rules targeting command-line patterns that utilize 'call' combined with variable assignment, and patterns involving 'timeout' combined with 'del' inside 'cmd.exe'.
- Implement monitoring for PowerShell or CMD activity that originates from non-system users to identify suspicious script execution.
- Investigate alerts triggered by automated deletion commands to determine if they represent legitimate administrative task cleanup or malicious activity.
