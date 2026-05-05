---
title: Get-Variable.exe Hijacking for Persistence
slug: 2024-01-03-get-variable-hijack
description: Attackers can establish persistence by placing a malicious Get-Variable.exe in the WindowsApps folder, hijacking the legitimate PowerShell cmdlet and executing upon PowerShell window initialization, as seen with the Colibri malware.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - powershell
  - windowsapps
  - colibri
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574.008
    technique_name: Hijack Execution Flow
references:
  - https://thehackernews.com/2022/04/researchers-uncover-how-colibri-malware.html
rules:
  - title: Detect Get-Variable.exe Execution from WindowsApps
    description: Detects execution of Get-Variable.exe from the WindowsApps directory, indicating potential cmdlet hijacking.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1574.008
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerShell Execution from Suspicious WindowsApps Path
    description: Detects PowerShell being executed from the WindowsApps path.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1574.008
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat involves the hijacking of the PowerShell `Get-Variable` cmdlet to achieve persistence. Attackers place a malicious executable named `Get-Variable.exe` within the `C:\Users\<user>\AppData\Local\Microsoft\WindowsApps` folder, which is included in the system's PowerShell path. When a PowerShell window is opened, including through scheduled tasks or other automated means, the malicious `Get-Variable.exe` is executed instead of the legitimate PowerShell cmdlet. This technique allows the attacker to run arbitrary code whenever a PowerShell session is initialized. This activity has been associated with the Colibri malware family. This technique is a stealthy way to maintain access to a compromised system, as the execution is triggered by a standard system process. Defenders need to monitor for unexpected executables running from within the WindowsApps directory to identify and prevent this form of persistence.

## Attack Chain

1.  Initial compromise of the system through an unrelated vulnerability or credential theft.
2.  The attacker gains access to the file system with sufficient privileges to write to the `C:\Users\<user>\AppData\Local\Microsoft\WindowsApps` directory.
3.  The attacker drops a malicious executable named `Get-Variable.exe` into the `WindowsApps` folder, effectively hijacking the legitimate PowerShell cmdlet.
4.  The attacker creates or modifies a scheduled task that launches PowerShell.exe.
5.  When the scheduled task triggers the PowerShell.exe execution, the system resolves `Get-Variable` to the malicious executable in the `WindowsApps` directory due to path precedence.
6.  The malicious `Get-Variable.exe` executes the attacker's payload.
7.  The attacker's payload performs malicious activities, such as establishing a reverse shell, downloading additional malware, or exfiltrating data.
8.  The attacker maintains persistent access to the compromised system.

## Impact

Successful exploitation leads to persistent access on the targeted system. The attacker can execute arbitrary code whenever a PowerShell window is opened, allowing them to perform various malicious activities, including data theft, ransomware deployment, or further propagation within the network. The Colibri malware, which has been associated with this technique, demonstrates the potential for significant compromise. The number of victims and specific sectors targeted vary depending on the attacker's objectives.

## Recommendation

*   Monitor process creation events for `Get-Variable.exe` executing from within the `C:\Users\<user>\AppData\Local\Microsoft\WindowsApps` directory using the Sigma rule `Detect Get-Variable.exe Execution from WindowsApps`.
*   Investigate any processes executing from the `WindowsApps` folder, as this is not a typical location for legitimate executables.
*   Implement application control policies to restrict the execution of unsigned or untrusted executables from the `WindowsApps` directory.
*   Enable Sysmon process creation logging to capture the necessary events for the Sigma rules in this brief.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
