---
title: New Abuse of Microsoft ClickOnce Technology for Initial Access and Persistence
slug: 2026-07-clickonce-abuse
description: Threat actors are exploiting Microsoft's ClickOnce technology, specifically leveraging its user-friendly deployment and update mechanisms via .application and .appref-ms files, to achieve initial access, establish persistence, and execute malware on Windows systems with minimal user interaction and without requiring elevated privileges.
date: "2026-07-07T12:22:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - clickonce
  - persistence
  - initial-access
  - execution
  - defense-evasion
vendors:
  - Microsoft
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Persistence via Startup Folder
    description: Detects the creation of a ClickOnce application reference file (.appref-ms) in a user's Startup folder, which indicates an attempt to establish persistence.
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

Threat actors are increasingly weaponizing Microsoft's legitimate ClickOnce technology, as highlighted by CrowdStrike, to bypass traditional security controls and establish persistent access on target systems. This abuse leverages ClickOnce's minimal user interaction requirement for application deployment, often via `.application` files, allowing malware to be executed and persist on a system without requiring elevated privileges. A key vector involves the `application reference file` (`.appref-ms`) dropped in the Start Menu, which provides a built-in updating mechanism. Adversaries can control the deployment server, pushing malicious updates that are automatically fetched and executed when the user launches the application, effectively turning a benign app into a malicious one. This method capitalizes on a general lack of awareness around ClickOnce apps and the stealth provided by malware executing within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`.

## Attack Chain

1.  **Initial Access / User Execution:** The attacker convinces a user, via social engineering (e.g., malicious link, email), to initiate the download and deployment of a seemingly benign ClickOnce application from a controlled server or an `.application` file.
2.  **Application Deployment:** The user clicks to install the ClickOnce application, which bypasses typical executable scrutiny and does not require administrator privileges.
3.  **Payload Execution Environment:** The malicious payload within the ClickOnce application begins execution, often hosted within legitimate Microsoft processes such as `dfsvc.exe` (Deployment Services Client) and `rundll32.exe`, increasing stealth.
4.  **Persistence Mechanism Deployment:** The ClickOnce installation drops an `application reference file` (`.appref-ms`) in the user's Start Menu, under `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`.
5.  **Persistence Establishment:** The attacker modifies the system to ensure the malicious `.appref-ms` file is automatically launched (e.g., by placing it in the Startup folder or creating a scheduled task referencing it).
6.  **Update Mechanism Abuse:** The attacker can later push malicious updates to the deployment server. When the user launches the `.appref-ms` shortcut, the system automatically fetches and executes the updated, malicious components without further user prompts.
7.  **Command and Control / Impact:** The updated malware establishes command and control, facilitates further lateral movement, exfiltrates data, or delivers final stage payloads like ransomware, all while maintaining persistence and leveraging the legitimate ClickOnce update mechanism.

## Impact

Successful exploitation of ClickOnce technology allows threat actors to gain initial access and establish persistent footholds within enterprise environments without requiring administrative privileges, bypassing common security mechanisms like mailbox filters. This can lead to the silent installation and updating of malware, including remote access tools or information stealers. The attacker maintains control over the deployed application, enabling them to change C2 infrastructure, exfiltrate sensitive data, or deploy new payloads over time. The widespread adoption of Windows and the legitimate nature of ClickOnce make this a potent attack vector against standard user accounts across various sectors.

## Recommendation

*   Enable `file_event` logging for user `Startup` directories and deploy the `Detect ClickOnce Persistence via Startup Folder` Sigma rule to identify malicious `.appref-ms` file creations.
*   Educate users on the risks associated with installing software from untrusted sources, even if it appears to be a legitimate application deployment initiated by a web click.
*   Monitor for network connections initiated by `dfsvc.exe` (Deployment Services Client) to untrusted or suspicious external domains that may indicate C2 activity.
*   Review and restrict the ability of standard users to install ClickOnce applications if not required for business operations, using application whitelisting or similar controls.
