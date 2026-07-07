---
title: New Abuse of ClickOnce Technology for Persistent Malware Deployment
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are weaponizing Microsoft's ClickOnce technology to achieve initial access, execute malicious payloads, and maintain persistence on target systems by leveraging its minimal user interaction, legitimate process execution, and built-in update mechanism, enabling stealthy long-term access.
date: "2026-07-07T14:28:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - defense-evasion
  - initial-access
  - malware
  - windows
vendors:
  - Microsoft
products:
  - ClickOnce Technology
  - Microsoft Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: ClickOnce applications can be deployed from .application files, which requires equally minimal user input
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries... For instance, by placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)...Further, the UI displayed to the user is a legitimate one from Microsoft.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: When configured to be available offline...whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
iocs:
  - type: file_name
    value: .application files
  - type: file_name
    value: .appref-ms
  - type: file_name
    value: rundll32.exe
  - type: file_name
    value: dfsvc.exe
  - type: path
    value: '%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\'
ioc_counts:
  file_name: 4
  path: 1
---

CrowdStrike has identified a new wave of abuse targeting Microsoft's ClickOnce technology, a legitimate application deployment framework, leveraged by threat actors for initial access, execution, and persistence since at least June 2026. Attackers capitalize on ClickOnce's minimal user interaction requirement and the lack of awareness surrounding .application files, often bypassing traditional email and endpoint defenses. This method allows malware deployment without elevated privileges, executing payloads within trusted Microsoft processes like `rundll32.exe` and `dfsvc.exe`. A key abuse involves weaponizing the built-in update mechanism: by compromising legitimate ClickOnce servers or tricking users into installing a benign app, adversaries can later push malicious updates, maintaining remote access and evolving their malware. The campaign targets a broad range of Windows users, posing a significant risk to organizations due to its stealth and efficacy in establishing long-term presence.

## Attack Chain

1.  Threat actors convince a user to interact with a deceptive link or `.application` file to initiate a ClickOnce application deployment.
2.  The user clicks, triggering the ClickOnce application deployment process which installs the malicious application on the system.
3.  The malicious payload executes within legitimate Microsoft process trees, specifically `rundll32.exe` and `dfsvc.exe`, to blend in with normal system activity and evade scrutiny.
4.  For applications configured for offline availability, a malicious `.appref-ms` file is dropped in the user's Start Menu, typically at `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`.
5.  The `.appref-ms` file is subsequently placed in the Windows `Startup` folder or a `scheduled task` is created to ensure the malicious ClickOnce application automatically runs upon system boot or at regular intervals.
6.  The built-in ClickOnce update mechanism is weaponized; the attacker pushes malicious updates to the deployment server, which are then silently downloaded and executed by the client application.
7.  The updated malicious application gains remote access, exfiltrates data, or performs further actions like lateral movement or C2 address changes, establishing a persistent foothold.

## Impact

If successful, the abuse of ClickOnce technology allows threat actors to establish persistent remote access to victim systems, exfiltrate sensitive data, or deploy additional malware. The attack vector bypasses traditional security controls by masquerading as legitimate software deployment and executing within trusted Microsoft processes. The lack of awareness among users regarding ClickOnce functionality further increases the success rate, enabling attackers to target standard user accounts without requiring elevated privileges. This widespread applicability across Windows environments makes it a potent threat, leading to compromised systems and potential data breaches for targeted organizations.

## Recommendation

*   Enable comprehensive logging for process creation, file system events, and scheduled tasks on Windows endpoints.
*   Monitor for the creation of `.application` and `.appref-ms` files in unusual or user-writable directories.
*   Alert on the creation of `.appref-ms` files within the `Startup` folder (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`) or in association with new scheduled tasks.
*   Investigate `rundll32.exe` or `dfsvc.exe` processes that launch unusual child processes or initiate suspicious network connections.
