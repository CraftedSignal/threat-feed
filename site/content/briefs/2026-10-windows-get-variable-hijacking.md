---
title: Abuse of PowerShell Search Path via WindowsApps Folder
slug: 2026-10-windows-get-variable-hijacking
description: Attackers can achieve persistence by placing a malicious 'Get-Variable.exe' binary into the WindowsApps folder to hijack PowerShell command execution, a technique observed in the wild by the Colibri malware.
date: "2026-10-12T18:07:37Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Colibri
tags:
  - persistence
  - privilege-escalation
  - powershell
  - colibri
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: An attacker can obtain persistence by hijacking the PowerShell cmdlet 'Get-Variable' by placing Get-Variable.exe in the WindowsApps folder.
    confidence_band: high
references:
  - https://thehackernews.com/2022/04/researchers-uncover-how-colibri-malware.html
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1574.008/T1574.008.yaml#L5
rules:
  - title: Detect Get-Variable.exe Execution from WindowsApps
    description: Detects the execution of Get-Variable.exe from the WindowsApps directory, which is a known persistence technique associated with the Colibri malware.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1574.008
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
    - action: Deploy the Sigma rule to monitor for Get-Variable.exe execution.
      owner: Detection Engineering
      due: 24h
      evidence: Source documentation of persistence technique.
  hunt_leads:
    - lead: Search for files named Get-Variable.exe within the local WindowsApps directory across the fleet.
      technique_id: T1574.008
      data_needed:
        - File system enumeration
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Technique relies on specific file path placement.
  mitigation_plan:
    - priority: medium
      action: Restrict write permissions for non-administrative users to the AppData folder structure.
      owner: IT Operations
      addresses: T1574.008
      evidence: Prevents unauthorized binary drop.
---

This threat involves the exploitation of the Windows search path mechanism to execute malicious code by hijacking the 'Get-Variable' PowerShell cmdlet. By placing a malicious executable named 'Get-Variable.exe' within the '%LocalAppData%\\Microsoft\\WindowsApps\\' directory, an attacker can ensure their binary is executed whenever PowerShell is invoked. Because the WindowsApps folder is included in the system's PATH, PowerShell will prioritize the malicious binary over the legitimate system functions under certain conditions. This technique, identified as T1574.008, allows for persistent code execution and has been observed in campaigns utilizing the Colibri malware. The primary concern for defenders is that this behavior often occurs when PowerShell windows are initialized, such as through legitimate scheduled tasks, masking the malicious activity behind normal system operations.

## Attack Chain

1. The attacker gains initial access to the target endpoint via phishing or secondary exploitation.
2. The attacker navigates to the user's local AppData path: %LocalAppData%\\Microsoft\\WindowsApps\\.
3. The attacker drops a malicious binary named 'Get-Variable.exe' into this directory.
4. The attacker establishes a persistence mechanism, such as a scheduled task, designed to trigger a PowerShell process.
5. The system or user triggers the scheduled task or launches a new PowerShell instance.
6. PowerShell resolves the 'Get-Variable' request by locating and executing the malicious 'Get-Variable.exe' in the WindowsApps folder.
7. The malicious code executes with the context of the calling PowerShell process, completing the persistence or privilege escalation cycle.

## Impact

The primary impact is the establishment of persistent, unauthorized code execution that survives system reboots and user logoffs. This technique can be used for privilege escalation and provides a stealthy foothold for additional stages of a campaign. It has been documented in active campaigns involving the Colibri malware, which can lead to data exfiltration or the deployment of additional payloads.

## Recommendation

1. Deploy the Sigma rule provided in this brief to monitor for the creation or execution of executables within the WindowsApps folder that deviate from standard naming conventions.
2. Implement EDR telemetry monitoring for 'Get-Variable.exe' process creation events (Sysmon Event ID 1 or Windows Event 4688) specifically originating from the WindowsApps path.
3. Audit the '%LocalAppData%\\Microsoft\\WindowsApps\\' directory for unauthorized or unrecognized executables.
4. Use the provided process-creation logs to verify the parent process, ensuring that legitimate administrative tools are not incorrectly flagged.
