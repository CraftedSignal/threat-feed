---
title: Suspicious PowerShell ConvertTo-SecureString Cmdlet Usage
slug: 2026-09-powershell-securestring
description: Detection of the ConvertTo-SecureString cmdlet usage via command-line, which is often used in adversarial scripts to handle credentials or obfuscated strings.
date: "2026-09-01T12:22:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - powershell
  - credential-theft
  - obfuscation
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: The cmdlet is often used by adversaries to handle credentials or obfuscated strings.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detection of the PowerShell cmdlet used to secure credentials.
    confidence_band: high
rules:
  - title: Detect ConvertTo-SecureString Cmdlet Usage
    description: Detects usage of the 'ConvertTo-SecureString' cmdlet via the command-line, which is fairly uncommon and could indicate potential suspicious activity
    platform: sigma
    severity: medium
    tactics:
      - execution
      - stealth
    techniques:
      - T1027
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Search command-line logs for ConvertTo-SecureString occurrences across the enterprise.
      technique_id: T1059.001
      data_needed:
        - Process creation events (Event ID 1)
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source document identifies this as a potential indicator of suspicious activity.
---

The usage of the 'ConvertTo-SecureString' cmdlet via the PowerShell command-line is often considered an uncommon operational pattern for standard administrative tasks. Adversaries frequently leverage this cmdlet to convert plain-text passwords into secure strings, facilitating their use in automated scripts or obfuscating credentials intended for downstream malicious processes. While legitimate administrative scripts may employ this cmdlet to pass credentials across different PowerShell sessions or modules, its direct invocation via a command-line interface warrants investigation, particularly when paired with encoded commands or non-standard parent processes. Defenders should treat this activity as a signal to inspect the broader context of the PowerShell execution chain, as it is a common precursor to credential materialization or privilege escalation activities.

## Impact

Successful exploitation of credential handling via this cmdlet may lead to unauthorized access to secured system resources, sensitive data exfiltration, or lateral movement within an organization's network if automated scripts are compromised.

## Recommendation

Deploy the provided Sigma rule to identify direct invocation of ConvertTo-SecureString and correlate these events with parent process activity to identify unauthorized credential handling.

- Enable PowerShell script block logging to augment command-line telemetry and provide deeper visibility into the execution context.
- Review and baseline existing administrative automation scripts that rely on this cmdlet to reduce false positives in the SIEM.
- Investigate any command-line execution where ConvertTo-SecureString is followed by execution of secondary processes or web-based network connections.
