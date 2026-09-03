---
title: Suspicious Hyper-V Cmdlet Execution
slug: 2026-09-hyper-v-cmdlets
description: Adversaries may use Hyper-V PowerShell cmdlets to create and manipulate virtual machines to conceal malicious activity or establish persistence.
date: "2026-09-03T13:42:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - stealth
  - persistence
  - windows
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: Adversaries may carry out malicious operations using a virtual instance to avoid detection
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.006/T1564.006.md#atomic-test-3---create-and-start-hyper-v-virtual-machine
rules:
  - title: Detect Suspicious Hyper-V Cmdlet Execution
    description: Detects the use of PowerShell cmdlets related to VM creation and configuration which may indicate an attempt to conceal activity within a virtual machine.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1564.006
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Search for script block logs containing Hyper-V cmdlets in non-standard execution paths
      technique_id: T1564.006
      data_needed:
        - Powershell Script Block Logging (Event ID 4104)
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source provides specific Hyper-V cmdlets often used in adversarial VM setup
---

Adversaries may abuse native Hyper-V management cmdlets to perform environment-based evasion. By creating, configuring, and starting virtual machines (VMs) via PowerShell, an attacker can isolate malicious activity within a virtualized instance, effectively hiding secondary stages or command-and-control communication from host-based security tools that may not have visibility into the guest OS or the virtualized environment. This technique is often used to establish stealthy persistence or to provide a sandbox environment for executing secondary payloads while avoiding direct interaction with the primary host filesystem or network stack. Monitoring for the misuse of these cmdlets in administrative or user-context scripts is essential for identifying potential efforts to weaponize the virtualization layer.

## Impact

Successful execution of these commands allows attackers to create stealthy infrastructure within an already compromised host. This can lead to persistent backdoors, secondary command-and-control channels, or the staging of further malicious operations, potentially complicating incident response and forensics as the malicious environment resides within a virtual disk file.

## Recommendation

* Enable PowerShell Script Block Logging (Event ID 4104) to capture the execution of specific Hyper-V management cmdlets.
* Deploy the provided Sigma rule to monitor for the creation or modification of virtual machines by unexpected processes.
* Establish a baseline of authorized administrative scripts that utilize Hyper-V cmdlets and tune alerting to exclude these signed or approved scripts.
