---
title: Security Software Discovery via PowerShell
slug: 2026-09-security-software-discovery
description: Adversaries use PowerShell script blocks to enumerate active security software processes by filtering system process listings for known defensive product names and company identifiers.
date: "2026-09-01T11:05:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - windows
  - powershell
  - reconnaissance
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1518
    technique_name: Software Discovery
    evidence: Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system.
    confidence_band: high
rules:
  - title: Detect Security Software Discovery via PowerShell
    description: Detects calls to get-process where the output is piped to a where-object filter to search for security solution processes.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1518.001
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging across Windows fleet.
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into script execution as per logsource.
  hunt_leads:
    - lead: Search for high-frequency usage of Get-Process cmdlets in logs.
      technique_id: T1518.001
      data_needed:
        - 4104 events
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Script block text analysis provides visibility.
  mitigation_plan:
    - priority: medium_term
      action: Restrict unprivileged users from executing PowerShell scripts.
      owner: Security Architecture
      addresses: T1518.001
      evidence: Hardens the endpoint against unauthorized reconnaissance.
  gaps:
    - Logging overhead for high-volume PowerShell activity.
---

Adversaries often perform reconnaissance on compromised systems to identify installed security controls, such as antivirus, EDR agents, and firewall configurations. A common technique for this discovery phase is the use of PowerShell to query the current running process list and filter the output for specific keywords associated with defensive vendors or products. By leveraging native cmdlets like 'Get-Process' (or the alias 'gps') in conjunction with 'Where-Object', attackers can programmatically determine which security sensors are active on a host. This information allows the attacker to tailor their subsequent actions, such as bypassing specific security product features, terminating processes, or avoiding specific file paths. The activity is observable through PowerShell Script Block Logging (Event ID 4104), which captures the full script content executed in a session.

## Attack Chain

1. An attacker gains initial access to a Windows host through a secondary vector.
2. The attacker initiates a PowerShell session to execute discovery commands.
3. The attacker executes a 'Get-Process' or 'gps' cmdlet to retrieve a list of all active system processes.
4. The output is piped to a 'Where-Object' (or '?') filter to parse the process list.
5. The script block evaluates process attributes such as 'Company', 'Description', 'Name', 'Path', or 'Product' against known security-related strings.
6. The script uses wildcards to match variants of security software names like 'defender', 'sentinel', or 'carbonblack'.
7. The attacker parses the filtered output to confirm which specific security agents are running.
8. Based on the findings, the attacker proceeds to tailor their post-exploitation behavior or evasion tactics.

## Impact

Successful discovery allows attackers to map the defensive landscape of an organization. By identifying the specific EDR or antivirus solution, an attacker can look up known bypasses, disable sensor features, or identify areas where security telemetry is lacking. This information gathering is a precursor to more severe impact, such as lateral movement, persistent access, or data exfiltration.

## Recommendation

1. Enable PowerShell Script Block Logging (Event ID 4104) via Group Policy to ensure visibility into script execution.
2. Deploy the provided Sigma rule to monitor for suspicious process enumeration patterns targeting security software.
3. Analyze telemetry for PowerShell scripts containing frequent usage of 'Get-Process' piped to 'Where-Object' filters looking for process attributes.
4. Establish a baseline of administrative scripts that utilize process enumeration to reduce false positives.
