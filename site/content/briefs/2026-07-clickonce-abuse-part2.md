---
title: Threat Actors Abuse ClickOnce for Stealthy Malware Delivery and Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are leveraging Microsoft's ClickOnce technology to deliver malware and achieve persistence on target systems, exploiting its minimal user interaction requirements, low security tool awareness of .application files, lack of elevated privilege needs, and built-in update mechanism via .appref-ms files or scheduled tasks, while executing within legitimate Microsoft processes like rundll32.exe and dfsvc.exe for stealth.
date: "2026-07-07T07:18:52Z"
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
  - ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system. This option significantly simplifies the delivery phase of the kill chain as it bypasses common protection mechanisms such as mailbox filtering systems.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload. [...] clicking a webpage button can trigger software installation, typically expecting to see an executable installer in their downloads folder first.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe).
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe).
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution. Further, the UI displayed to the user is a legitimate one from Microsoft.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: When opened, the .appref-ms gets the ClickOnce components to fetch available updates from the deployment server, download any potential new components, and run the application. [...] This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms File in Startup Folder
    description: Detects the creation of a ClickOnce .appref-ms shortcut file within a user's Startup folder, which attackers can use to achieve persistence on Windows systems by ensuring the application runs upon user login.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Scheduled Task Creating or Executing .appref-ms
    description: Detects the creation or modification of a scheduled task that is configured to execute a ClickOnce .appref-ms file, a known method for achieving persistence on Windows systems.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike has identified a new wave of abuse targeting Microsoft's ClickOnce technology, which threat actors are weaponizing for malware delivery and persistence since at least June 2026. This method is effective because it requires minimal user interaction for deployment, often bypassing traditional security controls like mailbox filters by using `.application` files. Attackers exploit the general lack of awareness among users and security tools regarding ClickOnce applications, which don't require elevated privileges for installation, making standard user accounts vulnerable. A key tactic involves dropping `.appref-ms` files for offline availability, allowing attackers to push malicious updates or establish persistence via the Windows Startup folder or scheduled tasks. The malicious payloads execute within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, further increasing stealth and defense evasion. This abuse significantly enhances the delivery and post-exploitation phases of the attack chain, making it crucial for defenders to implement specific monitoring and detection strategies.

## Attack Chain

1.  **Initial Access**: Threat actors send spearphishing emails or host malicious web content to convince targets to click a button or open an `.application` file.
2.  **Execution**: Upon user interaction, the ClickOnce application is installed without requiring elevated administrative privileges, directly executing the initial malicious payload.
3.  **Defense Evasion**: The malicious payload executes within legitimate Microsoft process trees, specifically observed using `rundll32.exe` and `dfsvc.exe`, to masquerade as benign activity.
4.  **Persistence - Shortcut Creation**: A legitimate `.appref-ms` file, which acts as a shortcut to the ClickOnce application, is dropped into the user's Start Menu programs folder (e.g., `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
5.  **Persistence - Autostart**: Attackers leverage this `.appref-ms` file by placing it into the Windows Startup folder to ensure automatic execution upon system boot or user login.
6.  **Persistence - Scheduled Task**: Alternatively, attackers create a scheduled task configured to regularly execute the `.appref-ms` file, maintaining persistent access.
7.  **Ingress Tool Transfer / Command and Control**: The built-in ClickOnce update mechanism is exploited; when the user launches the application (or it auto-starts), the application checks for updates from the attacker-controlled server, allowing malicious updates or new components to be downloaded and executed without further user prompts.
8.  **Impact**: Through the update mechanism, the attacker can update command and control (C2) addresses, deploy additional malware, move laterally, and exfiltrate data.

## Impact

Successful exploitation of this ClickOnce abuse vector leads to unauthorized code execution, malware deployment, and persistent access to victim systems without requiring administrator privileges. Organizations across all sectors are vulnerable, as the attack leverages a legitimate Windows feature and common user behaviors (clicking links, opening files). The stealthy execution within trusted Microsoft processes makes detection challenging, potentially leading to prolonged dwell times and severe consequences including data exfiltration, ransomware deployment, and lateral movement across the network. The ability to push updates via the ClickOnce mechanism ensures attackers can modify their payloads, evade evolving defenses, and maintain control over compromised endpoints.

## Recommendation

*   Enable verbose logging for process creation events, specifically for `dfsvc.exe` and `rundll32.exe`, to monitor for unusual child processes or loaded modules.
*   Deploy the Sigma rules in this brief to your SIEM and tune them for your environment to detect ClickOnce persistence mechanisms.
*   Review Group Policy Objects (GPOs) and endpoint security configurations to restrict execution of `.appref-ms` files from non-standard or user-writable locations.
*   Monitor for the creation and modification of scheduled tasks that involve `.appref-ms` files to detect `attack.t1053.005`.
*   Educate users on the risks associated with clicking suspicious links and opening unsolicited `.application` files, even if they appear to originate from trusted sources.
