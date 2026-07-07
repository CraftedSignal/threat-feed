---
title: 'New Abuse of ClickOnce Technology: Persistence and Evasion'
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are leveraging Microsoft's ClickOnce technology for initial access, defense evasion, and persistence by exploiting its user-friendly deployment, lack of user and security tool awareness, and the `.appref-ms` file update mechanism to execute malicious payloads within legitimate Microsoft processes without elevated privileges.
date: "2026-07-06T08:04:26Z"
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
  - windows
  - application-deployment
vendors:
  - Microsoft
products:
  - ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: clicking a webpage button can trigger software installation, typically expecting to see an executable installer in their downloads folder first.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: ""
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: ""
    evidence: an application reference file (.appref-ms) is dropped at the installation of the application in the Start Menu (under %Users \AppData\Roaming\Microsoft\Windows\Start Menu\Programs\)... By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: ""
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening... by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: ""
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution. Further, the UI displayed to the user is a legitimate one from Microsoft.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect Suspicious ClickOnce Payload Execution via Rundll32 or DFsvc
    description: Detects execution of malicious ClickOnce payloads by rundll32.exe or dfsvc.exe from the local ClickOnce application cache (`Apps\2.0`), which is indicative of an attacker abusing the ClickOnce update mechanism for persistence and execution.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.004
      - T1218.007
    data_sources:
      - process_creation
      - windows
  - title: Detect Creation of ClickOnce .appref-ms File in Unusual Location
    description: Detects the creation of a ClickOnce application reference file (`.appref-ms`) outside of the standard user Start Menu Programs directory, which could indicate an attempt to establish persistence or user-initiated malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Unspecified threat actors are actively exploiting Microsoft's ClickOnce technology, building on previously identified abuse vectors and introducing what is believed to be a new method for persistent access and defense evasion. The attack begins by deceiving users into initiating the deployment of a seemingly benign ClickOnce application, often through misleading website buttons or directly via `.application` files, effectively bypassing common security controls like mailbox filtering. This method is particularly effective as it requires minimal user interaction and no elevated privileges, allowing adversaries to target standard user accounts. Once installed, the malicious update mechanism inherent to ClickOnce is abused via the `.appref-ms` shortcut file. Every time the user launches the application, the attacker can push malicious updates from their controlled server, ensuring persistence and enabling dynamic C2 changes or lateral movement. Execution occurs within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, significantly enhancing stealth and evading traditional security scrutiny typically focused on `exe` files.

## Attack Chain

1.  Threat actors lure a user to a malicious website or distribute a malicious `.application` file.
2.  The user is convinced to click a misleading button on a webpage or open the `.application` file, initiating the ClickOnce application deployment.
3.  A seemingly harmless ClickOnce application is installed on the user's system, dropping an `.appref-ms` shortcut file in the user's Start Menu programs folder (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
4.  The attacker pushes a malicious update to the ClickOnce deployment server, effectively transforming the benign application into a malicious one.
5.  The next time the user launches the application via the `.appref-ms` shortcut, the ClickOnce components automatically fetch and download the malicious update without further user authorization.
6.  The newly updated malicious payload is executed within legitimate Microsoft process trees, such as `rundll32.exe` or `dfsvc.exe`, to evade detection.
7.  The attacker establishes persistence, maintains remote access, updates command and control (C2) addresses, and can facilitate lateral movement within the compromised environment.

## Impact

The successful exploitation of ClickOnce technology grants threat actors a stealthy and persistent foothold within enterprise environments. By leveraging the built-in update mechanism, adversaries can continuously maintain remote access, update their malware with new capabilities, modify command and control (C2) infrastructure, and facilitate lateral movement across the network. While specific victim counts or targeted sectors are not provided, the broad applicability of ClickOnce and the lack of awareness among users and security tools suggest a wide potential impact across any organization utilizing Windows endpoints. The abuse enables long-term presence and unchecked malicious activity, leading to data exfiltration, system compromise, or further malicious operations.

## Recommendation

*   Deploy the Sigma rules provided in this brief to detect suspicious ClickOnce update mechanisms and process execution.
*   Configure endpoint detection and response (EDR) solutions to monitor for the creation and execution of `.appref-ms` files, particularly when originating from untrusted sources or found in unusual directories outside the standard Start Menu path, as highlighted by Rule "Detect Creation of ClickOnce .appref-ms File in Unusual Location".
*   Implement strict policies on application whitelisting to prevent unauthorized ClickOnce application deployments that could facilitate initial access.
*   Educate users about the risks associated with installing software from untrusted sources, even if it appears to be a legitimate application deployment.
