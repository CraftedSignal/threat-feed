---
title: Detection of Malicious PowerShell CIM Session Abuse
slug: 2026-10-powershell-cim-abuse
description: This brief details the detection of potential lateral movement and remote code execution via the abuse of 'New-CIMSession' and 'Invoke-CIMMethod' cmdlets in PowerShell.
date: "2026-10-12T17:55:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - execution
  - powershell
  - wmi
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: The following analytic detects the creation of a New-CIMSession cmdlet followed by the use of the Invoke-CIMMethod cmdlet within PowerShell.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: This activity is significant because it mirrors the behavior of the Invoke-WMIMethod cmdlet, often used for remote code execution.
    confidence_band: high
rules:
  - title: Detect PowerShell CIM Session Abuse
    description: Detects the use of New-CimSession followed by Invoke-CIMMethod in PowerShell, which can indicate lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - lateral-movement
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (4104) across enterprise.
      owner: IT Operations
      due: 72h
      evidence: Required for the analytic described in the brief.
  hunt_leads:
    - lead: Search for instances of New-CimSession or Invoke-CIMMethod in historical 4104 logs.
      technique_id: T1047
      data_needed:
        - EventID 4104
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Analytic detects this specific cmdlet usage.
  mitigation_plan:
    - priority: medium_term
      action: Restrict remote management access to authorized jump hosts.
      owner: IT Security
      addresses: T1047
      evidence: Prevents unauthorized use of CIM/WMI.
---

This detection focuses on identifying the abuse of Common Information Model (CIM) cmdlets within PowerShell, specifically 'New-CIMSession' and 'Invoke-CIMMethod'. These cmdlets are standard administrative tools used to interact with Windows Management Instrumentation (WMI), but they are frequently repurposed by adversaries to execute commands on remote systems. This technique mirrors the behavior historically associated with 'Invoke-WMIMethod', which is often utilized for lateral movement, pass-the-hash attacks, and remote command execution within Windows environments. Defenders should monitor PowerShell Script Block Logging (Event ID 4104) to identify instances where these cmdlets are executed in sequence, as this is a high-signal indicator of unauthorized administrative-style activity.

## Attack Chain

1. Attacker gains initial access to a compromised host within the domain.
2. Attacker performs internal reconnaissance to identify high-value targets or servers.
3. Attacker uses compromised credentials to initiate a remote session using 'New-CIMSession'.
4. Attacker executes malicious payloads on the remote target using 'Invoke-CIMMethod'.
5. The WMI service on the target system executes the requested method.
6. If successful, the attacker achieves arbitrary code execution on the remote system.
7. Attacker continues lateral movement or data exfiltration from the compromised remote system.

## Impact

Successful abuse of these cmdlets can lead to unauthorized remote code execution, full system compromise, and further lateral movement throughout an Active Directory environment. This behavior is commonly associated with threat actors engaged in targeted intrusions and data theft, where stealthy administrative commands are preferred to bypass traditional security controls.

## Recommendation

* Enable PowerShell Script Block Logging (Event ID 4104) on all endpoints to capture the full execution context of scripts.
* Deploy the provided Sigma rule to identify the sequence of 'New-CIMSession' and 'Invoke-CIMMethod' being invoked within the same script block.
* Establish a baseline for legitimate administrative usage of CIM cmdlets in your environment to reduce false positives during investigation.
* Investigate occurrences of these cmdlets, particularly when initiated by non-administrative users or from unauthorized source machines.
