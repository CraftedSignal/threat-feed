---
title: Threat Actors Actively Abusing Microsoft ClickOnce for Malware Deployment and Persistence
slug: 2026-07-clickonce-abuse-part-2
description: Threat actors are exploiting Microsoft's ClickOnce technology to deploy and persist malware on target systems, leveraging minimal user interaction with malicious links or `.application` files to bypass traditional defenses and achieve stealthy execution within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, while also abusing its built-in update mechanism and persistence features via `.appref-ms` files.
date: "2026-07-06T07:15:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - endpoint-security
  - persistence
  - defense-evasion
  - windows
  - clickonce
vendors:
  - Microsoft
products:
  - ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system. ... ClickOnce applications can be deployed from .application files, which requires equally minimal user input.
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
    evidence: By placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1133
    technique_name: External Remote Services
    evidence: When opened, the .appref-ms gets the ClickOnce components to fetch available updates from the deployment server, download any potential new components, and run the application. ... All they have to do is push a malicious update into the deployment server, and the next time the user opens the .appref-ms file of the app, the malicious payload will be downloaded and run without the user realizing the application has changed.
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect Execution of ClickOnce .application Files
    description: Detects the execution of ClickOnce `.application` files, which threat actors abuse for initial access and malware deployment. This behavior can bypass traditional security controls.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.002
      - T1218.007
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce .appref-ms Persistence
    description: Detects the creation or modification of ClickOnce `.appref-ms` files in common user persistence locations, such as the Startup folder, which indicates an attempt to establish persistence.
    platform: sigma
    severity: high
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

Threat actors are increasingly weaponizing Microsoft's ClickOnce technology, a legitimate application deployment framework, to deliver and maintain persistence for their malware. This technique exploits the user-friendly nature of ClickOnce, requiring minimal interaction (just one or two clicks) to execute payloads, thereby bypassing common security mechanisms like email filtering and traditional executable scrutiny. Attacks involve tricking users into clicking malicious links or opening specially crafted `.application` files. A key concern is the general lack of awareness around ClickOnce applications, allowing malicious installations to "fly under the radar" of both users and security tools. Adversaries further benefit from ClickOnce's ability to install applications without elevated privileges and its built-in updating mechanism, which can be abused to transform benign applications into malicious ones post-installation. Malicious payloads execute within legitimate Microsoft processes, `rundll32.exe` and `dfsvc.exe`, enhancing stealth and evasion capabilities, making detection challenging for defenders.

## Attack Chain

1.  **Initial Access**: Threat actors send spearphishing emails containing malicious links or attachments that, when clicked, initiate the download and deployment of a ClickOnce application (`.application` file). Alternatively, users are lured to websites hosting these malicious `.application` files.
2.  **Execution**: The user clicks the link or `.application` file, triggering the ClickOnce deployment process. The embedded malicious payload executes on the system, often masquerading its execution within legitimate Microsoft processes such as `rundll32.exe` or `dfsvc.exe`.
3.  **Local Application Deployment**: The malicious ClickOnce application installs itself on the system. If configured for offline access, an application reference file (`.appref-ms`) is dropped into the user's Start Menu programs directory (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
4.  **Persistence via Startup Folder**: To ensure continued execution, adversaries place the `.appref-ms` file into the Windows Startup folder (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`), causing the ClickOnce application to launch automatically upon system boot.
5.  **Persistence via Scheduled Task**: As an alternative or additional persistence mechanism, threat actors can create a scheduled task to periodically launch the `.appref-ms` file, ensuring the malicious ClickOnce application is regularly executed.
6.  **Update Mechanism Abuse**: The `.appref-ms` file can trigger updates from a deployment server controlled by the attacker. This allows the attacker to push new malicious components or transform a seemingly benign installed application into a fully compromised one without further user interaction or notification.
7.  **Impact**: The malicious ClickOnce application establishes command and control (C2), facilitates remote access, exfiltrates sensitive data, or enables further malicious activities like lateral movement or ransomware deployment.

## Impact

The abuse of ClickOnce technology poses a significant threat due to its ability to bypass common security controls, achieve stealthy execution within legitimate processes, and establish robust persistence mechanisms. The user-friendly deployment process, coupled with a general lack of awareness, increases the success rate of initial compromise. If successful, this can lead to unauthorized remote access, data exfiltration, deployment of additional malware, and full system compromise without requiring administrator privileges. The built-in update functionality allows attackers to continuously evolve their payloads, making long-term detection and remediation more challenging. This method impacts organizations across all sectors, as it targets common user behavior and leverages a widely available Microsoft technology.

## Recommendation

*   **Implement detection for `.application` file execution**: Deploy the "Detect Execution of ClickOnce `.application` Files" Sigma rule to monitor for suspicious ClickOnce application launches, particularly from untrusted sources or parent processes.
*   **Monitor for `.appref-ms` file creation in persistence locations**: Implement the "Detect ClickOnce `.appref-ms` Persistence" Sigma rule to detect the creation of `.appref-ms` files in critical locations like user Startup folders, which indicates an attempt at persistent execution.
*   **Enable comprehensive endpoint logging**: Ensure `process_creation` and `file_event` logging are enabled on all Windows endpoints to provide the telemetry required for the detection rules above.
*   **Educate users on ClickOnce risks**: Conduct security awareness training highlighting the risks associated with clicking links or opening unsolicited `.application` files, even if they appear to originate from legitimate sources.
