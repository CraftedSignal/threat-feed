---
title: 'New Abuse of ClickOnce Technology: Persistence via .appref-ms Files'
slug: 2026-07-clickonce-abuse
description: Threat actors are increasingly abusing Microsoft's ClickOnce technology, using its user-friendly deployment, lack of awareness, and built-in update mechanism to achieve initial access, execute malware within legitimate process trees, and establish stealthy persistence by dropping .appref-ms files in startup folders or via scheduled tasks, enabling reliable remote access and C2.
date: "2026-07-07T12:44:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - initial-access
  - malware
  - windows
  - defense-evasion
vendors:
  - Microsoft
products:
  - Windows ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: ClickOnce applications also provide threat actors with a built-in updating mechanism... whoever controls the server can update the app.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence in Startup Folders
    description: Detects the creation of ClickOnce .appref-ms shortcut files within Windows Startup folders, a common persistence mechanism abused by threat actors.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

Threat actors are actively leveraging Microsoft's ClickOnce technology for malicious purposes, exploiting its design to achieve stealthy initial access, execution, and persistence. This abuse capitalizes on the minimal user interaction required for ClickOnce deployments, often bypassing traditional security defenses like email filters by using `.application` files. Attackers benefit from the general lack of awareness surrounding ClickOnce, as users may unknowingly install malicious applications by clicking seemingly innocuous web buttons. A key advantage for adversaries is that ClickOnce applications do not require elevated privileges for deployment, allowing them to target standard user accounts. Furthermore, the built-in updating mechanism can be weaponized; once an application is installed, threat actors can push malicious updates to maintain remote access and adapt their command and control (C2) infrastructure without further user prompts. Malicious payloads execute within legitimate Microsoft process trees, such as `dfsvc.exe` and `rundll32.exe`, increasing stealth and evading detection.

## Attack Chain

1.  **Initial Access**: A user is lured by a phishing email or malicious website to click a link or download a `.application` file that initiates a ClickOnce deployment.
2.  **Execution**: The user interaction triggers the ClickOnce deployment process, which launches `dfsvc.exe` to manage the application installation and updates.
3.  **Payload Delivery**: `dfsvc.exe` then executes `rundll32.exe` to download and run the initial malicious payload from an attacker-controlled deployment server.
4.  **Persistence Establishment**: A shortcut file (`.appref-ms`) for the malicious ClickOnce application is dropped into the user's Start Menu programs folder (e.g., `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
5.  **Automated Persistence**: For more robust persistence, the `.appref-ms` file is placed directly into a Windows Startup folder or configured for automatic execution via a scheduled task.
6.  **Update Mechanism Abuse**: Upon subsequent launches (either manual or automated via persistence), the ClickOnce application contacts the attacker's deployment server for updates.
7.  **Command and Control**: The attacker pushes new, malicious components or command-and-control instructions as an update, which are then downloaded and executed by `dfsvc.exe` and `rundll32.exe` without user authorization.
8.  **Impact**: The attacker gains reliable remote access, maintains persistence, and can modify or extend their malicious activities on the compromised system.

## Impact

Successful exploitation of ClickOnce technology by threat actors can lead to widespread malware execution and persistent unauthorized access within an organization's network. Attackers can bypass traditional security controls, compromise standard user accounts without requiring administrative privileges, and maintain a covert presence through legitimate-looking Microsoft processes and built-in update mechanisms. This results in the loss of data confidentiality, integrity, and availability, and can be used for further lateral movement, data exfiltration, or deployment of ransomware, significantly impacting business operations and reputation. The stealthy nature of these attacks makes them challenging to detect and eradicate, potentially leading to long-term compromise.

## Recommendation

*   Deploy the Sigma rule detecting suspicious `.appref-ms` file creation in startup folders to your SIEM and tune for your environment.
*   Implement application whitelisting solutions to restrict the execution of unsigned or untrusted ClickOnce applications.
*   Enable Sysmon file event logging (Event ID 11 for FileCreate) to detect the creation of `.appref-ms` files in sensitive directories like startup folders.
*   Train users to identify and report suspicious links or `.application` file downloads that may lead to ClickOnce abuse.
