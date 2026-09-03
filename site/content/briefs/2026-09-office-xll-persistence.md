---
title: Abuse of Microsoft Office Add-in XLL Files for Persistence
slug: 2026-09-office-xll-persistence
description: Adversaries leverage the RegisterXLL COM method via PowerShell to execute malicious add-ins and achieve persistence within Microsoft Office environments.
date: "2026-09-03T13:41:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - office-add-in
  - powershell
  - windows
  - threat-detection
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1137
    technique_name: Office Application Startup
    evidence: Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system.
    confidence_band: high
rules:
  - title: Detect PowerShell RegisterXLL COM Method Usage
    description: Detects the use of the RegisterXLL method via PowerShell COM objects, a technique used for Office add-in persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1137.006
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
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints.
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into the RegisterXLL TTP.
  hunt_leads:
    - lead: Search 4104 logs for instances of '.RegisterXLL' method calls.
      technique_id: T1137.006
      data_needed:
        - Event ID 4104
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Method invocation is a high-fidelity signal for this persistence technique.
  mitigation_plan:
    - priority: medium_term
      action: Restrict unauthorized Office add-in loading via Group Policy.
      owner: IT Operations
      addresses: T1137.006
      evidence: Technique relies on the loading of external libraries via Office.
  gaps:
    - Absence of endpoint visibility where Script Block Logging is not enabled.
---

Adversaries abuse the Microsoft Office Add-in architecture to establish persistence on compromised systems. By utilizing the COM interface, specifically the RegisterXLL method, attackers can load arbitrary dynamic link libraries (DLLs) disguised as Office add-ins into the memory space of Office applications. This technique is often executed via PowerShell scripts, allowing for stealthy code execution that persists across sessions or is triggered upon the initiation of Office processes. This method is documented in the Atomic Red Team framework under T1137.006, highlighting its utility for maintaining a foothold in environments where Office applications are regularly used. Detection relies on monitoring PowerShell script block activity for specific COM object instantiation and method invocation, necessitating that Script Block Logging (Event ID 4104) is enabled across the endpoint environment.

## Attack Chain

1. Attacker gains initial code execution on a target endpoint via phishing or secondary exploit.
2. Attacker writes a malicious DLL (XLL) file to a local directory.
3. Attacker executes a PowerShell script to interact with the Office COM interface.
4. The script initializes an Office application (e.g., Excel) via `New-Object -ComObject`.
5. The PowerShell script invokes the `.RegisterXLL` method on the initialized application object.
6. The Office application loads the malicious XLL file from the specified path.
7. The code within the XLL executes within the context of the Office process.
8. Malicious code establishes long-term persistence or communicates with an attacker-controlled C2 server.

## Impact

Successful exploitation allows for stealthy, process-resident persistence within Microsoft Office, enabling attackers to execute arbitrary code, perform credential harvesting, or exfiltrate sensitive data whenever the user interacts with the compromised Office application.

## Recommendation

1. Enable PowerShell Script Block Logging (Event ID 4104) on all Windows endpoints to ensure the execution of RegisterXLL commands is captured.
2. Deploy the provided Sigma rule to detect the specific COM object registration pattern in PowerShell logs.
3. Implement endpoint controls to restrict the loading of unsigned or non-standard add-ins in Office applications.
4. Monitor for unauthorized or suspicious DLL creation and modification in Office-related directories.
