---
title: Nimbus Manticore Resurfaces During Operation Epic Fury with New Techniques
slug: 2026-05-nimbus-manticore
description: Nimbus Manticore, an Iranian IRGC-affiliated threat actor, resurfaced during Operation Epic Fury, employing AppDomain Hijacking, SEO poisoning, and a new MiniFast backdoor while targeting the aviation and software sectors.
date: "2026-05-22T15:18:05Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Nimbus Manticore
tags:
  - nimbus-manticore
  - irgc
  - appdomain-hijacking
  - seo-poisoning
  - minijunk
  - minifast
  - infostealer
vendors:
  - Microsoft
  - OnlyOffice
  - Accenture
  - Zoom
products:
  - Setup.exe
  - OnlyOffice
  - Zoom Installer
  - MiniJunk
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/
rules:
  - title: Detect AppDomain Hijacking via Setup.exe
    description: Detects AppDomain Hijacking by monitoring for Setup.exe loading uevmonitor.dll, as used by Nimbus Manticore.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
  - title: Detect MiniJunk File Creation
    description: Detects the creation of MiniJunk files in the user's AppData\Local\Packages directory.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Nimbus Manticore (UNC1549), an Iranian IRGC-affiliated threat actor, resurfaced during Operation Epic Fury in February 2026, targeting the defense, aviation, and telecommunication sectors. The actor employed new techniques, including AppDomain Hijacking, AI-assisted malware development for its MiniFast backdoor, and SEO poisoning, demonstrating enhanced capabilities. The campaign used phishing lures impersonating organizations in the aviation and software sectors across the United States, Europe, and the Middle East. The actor also abused a Zoom installer's execution flow to stage a time-sensitive infection chain, blending malicious activity with legitimate system processes. This resurgence indicates the actor's rapid adaptation and operational availability during periods of geopolitical tension.

## Attack Chain

1. **Initial Access:** Spear-phishing emails are sent to employees in the aviation and software sectors with fake career opportunities.
2. **Lure Delivery:** Victims are directed to download a ZIP archive hosted on platforms like OnlyOffice.
3. **AppDomain Hijacking:** The ZIP file contains a benign `Setup.exe`, a malicious `Setup.exe.config` file that hijacks the application domain, `uevmonitor.dll` (first-stage dropper), and a benign `Interop.TaskScheduler.dll`.
4. **First Stage Execution:** Executing `Setup.exe` loads `uevmonitor.dll`, which extracts and deploys the next-stage payload.
5. **MiniJunk Deployment:** The dropper writes files into `C:\Users\<USER>\AppData\Local\Packages\`, including a legitimate executable for DLL sideloading and a malicious DLL identified as a new version of the MiniJunk backdoor.
6. **Zoom Installer Abuse:** A malicious DLL is sideloaded into a legitimate Zoom installer to execute code.
7. **MiniFast Backdoor Installation:** The new MiniFast backdoor is installed, providing remote access and control.
8. **Persistence and Data Exfiltration:** The MiniFast backdoor establishes persistence and begins exfiltrating data from the compromised system.

## Impact

The Nimbus Manticore campaign targeted organizations in the aviation and software sectors across the United States, Europe, and the Middle East. Successful exploitation leads to the installation of the MiniFast backdoor, enabling data exfiltration and potential disruption of operations. This can compromise sensitive information, intellectual property, and critical infrastructure within the targeted sectors. The actor's enhanced capabilities, including AI-assisted malware development, allow for rapid adaptation and increased operational effectiveness during periods of conflict.

## Recommendation

*   Monitor process creation events for `Setup.exe` loading DLLs from unusual locations, specifically `uevmonitor.dll`, to detect AppDomain Hijacking (see Sigma rule `Detect AppDomain Hijacking via Setup.exe`).
*   Implement network monitoring for connections to known malicious domains associated with Nimbus Manticore, such as those listed in the referenced Checkpoint report.
*   Enable Sysmon logging for process creation and file creation events to capture the full attack chain, including the execution of `Setup.exe` and the creation of files in the `C:\Users\<USER>\AppData\Local\Packages\` directory.
*   Deploy the Sigma rule `Detect MiniJunk File Creation` to identify files written to the user's AppData\\Local\\Packages directory, which is indicative of MiniJunk deployment.
