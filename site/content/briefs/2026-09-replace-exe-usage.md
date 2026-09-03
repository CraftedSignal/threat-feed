---
title: Abuse of Replace.exe Living-off-the-Land Binary
slug: 2026-09-replace-exe-usage
description: Adversaries can abuse the legitimate Windows utility replace.exe to overwrite system files or replace existing binaries with malicious versions, facilitating persistence or privilege escalation.
date: "2026-09-03T13:46:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lolbin
  - persistence
  - windows
  - privilege-escalation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: The utility can be used to transfer/replace files on a target system.
    confidence_band: high
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Replace/
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/replace
rules:
  - title: Detect Replace.exe Usage
    description: Detects the use of Replace.exe with the -a argument which can be used to add or replace files in a system directory
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Search for instances of replace.exe in process logs
      technique_id: T1105
      data_needed:
        - Process creation events (Event ID 1)
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source documentation identifies replace.exe as an abusable LOLBin.
  mitigation_plan:
    - priority: medium_term
      action: Restrict execution permissions for replace.exe to administrative service accounts
      owner: IT Operations
      addresses: LOLBin abuse
      evidence: Standard hardening practice for administrative tools
---

The Windows native utility replace.exe is a command-line tool designed to replace files in a directory or across a drive. While intended for administrative maintenance and software updates, threat actors leverage this binary to replace legitimate system or application files with malicious counterparts. This technique falls under the Living-off-the-Land Binaries (LOLBins) classification, as the tool is digitally signed by Microsoft and often overlooked by security controls. When combined with the '-a' argument, which adds files to a destination directory instead of replacing existing ones, or used to overwrite target binaries, attackers can achieve code execution or persistence. Defenders should monitor for unexpected execution of replace.exe, particularly when used with arguments that signify modification of system directories.

## Impact

Successful abuse of replace.exe can allow an attacker to gain persistence, escalate privileges by replacing sensitive system binaries, or deploy secondary malware payloads while avoiding detection by traditional file-integrity monitoring tools. This technique is applicable to any Windows environment where the attacker has gained sufficient user permissions to modify target file locations.

## Recommendation

Deploy the Sigma rule provided in this brief to detect the execution of replace.exe with specific command-line arguments. Enable Sysmon Process Creation (Event ID 1) logging and baseline administrative usage of replace.exe to reduce false positives in your environment.
