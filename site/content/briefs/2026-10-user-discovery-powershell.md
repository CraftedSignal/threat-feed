---
title: PowerShell User Discovery via Environment Variables
slug: 2026-10-user-discovery-powershell
description: Adversaries utilize PowerShell environment variables to perform user discovery on compromised Windows systems, aiding in situational awareness for lateral movement.
date: "2026-10-12T18:00:06Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - endpoint
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
    evidence: The following analytic detects the execution of powershell.exe with command-line arguments that use PowerShell environment variables to identify the current logged user.
    confidence_band: high
rules:
  - title: Detect User Discovery via PowerShell Environment Variables
    description: Detects the execution of PowerShell commands using environment variables to identify the current logged-in user.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1033
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for PowerShell discovery activity
      owner: Detection Engineering
      due: 7d
      evidence: Analytic provided by Splunk-ESCU
  hunt_leads:
    - lead: Search for PowerShell command lines containing environment variable discovery patterns
      technique_id: T1033
      data_needed:
        - Process creation logs with full command line
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Detection logic provided in source
---

Adversaries often perform system and user discovery on compromised Windows hosts to support lateral movement and privilege escalation. A common, low-noise technique involves executing PowerShell commands that query local environment variables, specifically $env:UserName or [System.Environment]::UserName, to confirm the identity of the current user. While these commands are simple, they provide critical context for an attacker to verify they have successfully accessed the desired account or to identify high-value users for further targeting. Defenders should monitor for PowerShell process executions that include these specific environment variable strings, as they are rarely required for legitimate day-to-day user tasks and often indicate post-exploitation activity.

## Impact

Successful execution of user discovery allows attackers to gather actionable intelligence about the compromised environment, facilitating targeted lateral movement and deeper exploitation. While this specific activity is not destructive, it is a precursor to more severe unauthorized access or data exfiltration within an Active Directory-managed environment.

## Recommendation

Deploy detection logic to identify PowerShell processes executing discovery commands and tune for administrative activity.
- Deploy the provided Sigma rule to your SIEM and tune for legitimate IT/admin scripts.
- Enable Sysmon (Event ID 1) or Windows Security Log (Event ID 4688) process creation logging, ensuring the command line is captured in full.
- Prioritize alerts originating from non-administrative service accounts or unusual parent processes.
