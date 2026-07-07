---
title: New Abuse of ClickOnce Technology for Stealthy Malware Delivery and Persistence
slug: 2026-07-clickonce-abuse
description: Threat actors are exploiting Microsoft's ClickOnce application deployment technology, specifically its update and persistence mechanisms via `.appref-ms` files, to bypass traditional security defenses and deliver malicious payloads within legitimate process trees on Windows systems.
date: "2026-07-04T09:43:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - execution
  - malware-delivery
  - windows
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system. This option significantly simplifies the delivery phase of the kill chain as it bypasses common protection mechanisms such as mailbox filtering systems. Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Another advantage of ClickOnce applications for adversaries lies in the fact that they don’t require elevated privileges to be deployed. While installing a .msi package requires administrator rights, any user can install a ClickOnce app. This lowers the barrier to entry for attacks, as threat actors can target standard user accounts
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Application Shortcut (.appref-ms) Persistence
    description: Detects the creation or modification of ClickOnce application shortcut files (.appref-ms) in known Windows startup or persistence locations, indicating potential abuse for malware persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.005
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious Child Processes from ClickOnce Deployment Service
    description: Detects the legitimate ClickOnce Deployment Service (dfsvc.exe) spawning unusual or potentially malicious child processes, indicating an active payload execution via abused ClickOnce updates.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1053
      - T1059.001
      - T1059.003
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Threat actors are increasingly abusing Microsoft's ClickOnce technology to deploy malware, leveraging its user-friendly installation process and the general lack of awareness around its security implications. ClickOnce allows applications to be installed with minimal user interaction and without requiring elevated privileges, making it an attractive vector for adversaries. The technique involves delivering a seemingly benign ClickOnce application, then exploiting its built-in update mechanism to push malicious payloads. This allows malware to execute within legitimate Microsoft processes like `dfsvc.exe` and `rundll32.exe`, increasing stealth and evading traditional defenses that scrutinize `.exe` files more closely than `.application` files. Furthermore, attackers can achieve persistence by strategically placing `.appref-ms` shortcut files in locations like the Windows Startup folder or via scheduled tasks, ensuring the malicious update is delivered upon each execution.

## Attack Chain

1.  **Initial Access - Delivery**: The user is lured into downloading a malicious ClickOnce `.application` file, or clicks on a deceptive webpage button that initiates the ClickOnce deployment process for a seemingly legitimate application.
2.  **Execution - Initial Deployment**: The user interacts with the `.application` file or prompt, causing the ClickOnce deployment service (`dfsvc.exe`) to download and execute the initial application, which might appear harmless or legitimate.
3.  **Persistence - Shortcut Creation**: If the ClickOnce application is configured for offline availability, a shortcut file (`.appref-ms`) is legitimately created and placed in the user's Start Menu for easy access.
4.  **Persistence - Abused Location**: The threat actor manipulates the system to place the `.appref-ms` file into a common persistence location, such as the Windows Startup folder (`%AppData%\Microsoft\Windows\Start Menu\Programs\Startup`) or configures a Scheduled Task to execute it automatically.
5.  **Command and Control - Malicious Update**: The threat actor compromises the ClickOnce deployment server (or controls it for their malicious app) and pushes a malicious update containing the actual payload.
6.  **Execution - Payload Delivery**: The user's system automatically launches the `.appref-ms` shortcut (e.g., via Startup or Scheduled Task). This triggers `dfsvc.exe` to check for updates, download the malicious update, and execute the final payload within the context of `dfsvc.exe` or `rundll32.exe`.

## Impact

The abuse of ClickOnce for malware delivery enables attackers to establish stealthy persistence and execute arbitrary code on targeted Windows systems. This method bypasses common email and endpoint security controls by leveraging legitimate Microsoft processes and application deployment mechanisms. Organizations can face data exfiltration, further compromise of the network through lateral movement, and ultimately, the deployment of ransomware or other destructive payloads. The lack of awareness among users and security tools regarding `.application` files lowers the barrier for successful attacks, making it easier for threat actors to compromise standard user accounts.

## Recommendation

*   Deploy the Sigma rule `Detect ClickOnce Application Shortcut (.appref-ms) Persistence` to identify `.appref-ms` files created in unusual persistence locations.
*   Deploy the Sigma rule `Detect Suspicious Child Processes from ClickOnce Deployment Service` to flag `dfsvc.exe` spawning unexpected or malicious child processes.
*   Enable Sysmon process-creation logging and file-creation logging on Windows endpoints to activate the rules above.
*   Educate users about the risks associated with unexpected software installations and `.application` files, emphasizing that not all installations require administrator privileges.
