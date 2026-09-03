---
title: Detection of WinRM Remote Management Enablement
slug: 2026-09-enable-winrm
description: Adversaries may enable Windows Remote Management (WinRM) to facilitate lateral movement and remote code execution on compromised systems.
date: "2026-09-03T13:38:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - powershell
  - winrm
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM).
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints.
      owner: IT Operations
      due: 7d
      evidence: Required for visibility into script execution.
  hunt_leads:
    - lead: Search historical 4104 logs for 'Enable-PSRemoting'.
      technique_id: T1021.006
      data_needed:
        - "4104"
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Provides insight into past lateral movement attempts.
---

Windows Remote Management (WinRM) is a legitimate management feature built into the Windows operating system. However, adversaries frequently target this service to gain a persistent, interactive, and authenticated remote access mechanism. By executing the 'Enable-PSRemoting' commandlet, an attacker can configure the system to accept remote connections, bypassing the default security posture that may restrict remote access to administrators or specific network segments. 

This technique is often employed after initial access has been achieved, as part of a lateral movement phase. Detection is critical as the command is typically executed in memory via PowerShell, leaving no disk-based footprints other than logs if Script Block Logging is enabled. Defenders should focus on PowerShell Script Block event logs, which provide deep visibility into the exact commands executed on endpoints.

## Impact

Successful enablement of WinRM provides an attacker with a high-privilege remote management interface. If exploited, this allows for the execution of arbitrary commands, exfiltration of data, and further propagation throughout the enterprise network. This technique is often used in the deployment phase of ransomware and post-exploitation toolkits.

## Recommendation

Deploy the provided Sigma rule to detect the execution of 'Enable-PSRemoting' across the environment. Ensure that PowerShell Script Block Logging (Event ID 4104) is enabled globally via Group Policy or MDM. Monitor for non-standard usage of this commandlet, particularly when initiated from processes that are not typically involved in system administration or configuration management.

## Rules

- title: "Detect Enable-PSRemoting Execution"
 description: "Detects the use of Enable-PSRemoting to configure WinRM, a common step for adversaries performing lateral movement."
 logsource:
 category: "ps_script"
 product: "windows"
 detection:
 selection:
 ScriptBlockText|contains: "Enable-PSRemoting "
 condition: "selection"
 level: "medium"
 tags:
 - "attack.lateral-movement"
 - "attack.t1021.006"
 tests:
 positive:
 - name: "Enable-PSRemoting executed in script"
 data:
 - ScriptBlockText: "Enable-PSRemoting -Force"
 negative:
 - name: "Normal system administration script"
 data:
 - ScriptBlockText: "Get-Service WinRM"
 falsepositives:
 - "Legitimate administrative configuration scripts run by authorized personnel."
 handoff:
 detection_confidence: "high"
 required_telemetry:
 - log_source: "PowerShell Script Block Logging"
 event_or_channel: "4104"
 required_fields:
 - "ScriptBlockText"
 availability: "needs_enablement"
 notes: "Requires Group Policy 'Turn on PowerShell Script Block Logging' to be enabled."
 validation:
 status: "test_defined"
 steps:
 - "Execute 'Enable-PSRemoting -Force' in a lab machine PowerShell instance."
 expected_telemetry: "Event ID 4104 containing the string 'Enable-PSRemoting'."
 pass_criteria: "Detection rule triggers on the 4104 event."
 atomic_reference: "T1021.006"
 known_evasions:
 - "Obfuscation of the command string using backticks or string concatenation."
 limitations:
 - "Only captures execution if Script Block Logging is enabled."
 tuning:
 - source: "System administration automation"
 guidance: "Baseline the known service accounts and scripts that legitimately perform this configuration."
 suggested_owner: "Detection Engineering"
