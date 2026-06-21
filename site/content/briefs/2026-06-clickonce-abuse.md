---
title: New Abuse of ClickOnce Technology for Malware Distribution
slug: 2026-06-clickonce-abuse
description: Threat actors are actively abusing Microsoft's ClickOnce technology, a legitimate application deployment mechanism, to spread malware by leveraging its user-friendly deployment process, often without requiring administrative privileges, enabling easy installation and persistence of malicious applications once a user initiates the deployment.
date: "2026-06-21T07:04:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware
  - application-deployment
  - windows
  - initial-access
  - execution
vendors:
  - Microsoft
products:
  - ClickOnce technology
  - Visual Studio
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
rules:
  - title: Detect ClickOnce Application Execution from Local Cache
    description: Detects process execution originating from the ClickOnce application cache (%LOCALAPPDATA%\Apps\2.0), which is a location known to be used by both legitimate and malicious ClickOnce deployed applications. This can indicate the successful execution of a deployed ClickOnce application.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1059
      - T1547.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious ClickOnce Deployment Service (dfsvc.exe) Invocation
    description: Detects suspicious command-line parameters used with dfsvc.exe, the Windows ClickOnce Deployment Support Service. Specifically looking for '-url:' which indicates deployment from a remote web server, a common vector for malicious ClickOnce applications.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce Application Manifest (.application) File Creation
    description: Detects the creation of '.application' files, which are ClickOnce deployment manifests. While legitimate, their appearance in suspicious directories like 'Downloads' followed by execution can indicate malicious activity.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1204.002
    data_sources:
      - file_event
      - windows
rules_count: 3
---

Threat actors are increasingly exploiting Microsoft's ClickOnce technology, a legitimate application deployment framework, to facilitate the distribution and execution of malware. ClickOnce simplifies software distribution by allowing users to run, install, and automatically update applications with minimal interaction and often without requiring administrative privileges. While designed to streamline developer-to-user software delivery, this "click-once" convenience presents a significant security risk. Adversaries are weaponizing this technology by crafting malicious ClickOnce applications that, once deployed, can establish persistence and execute payloads. The abuse leverages ClickOnce's features such as self-contained packaging, automatic updates, and a simplified installation wizard that can bypass traditional security prompts if users are socially engineered. This trend highlights a shift towards abusing trusted, built-in system functionalities to bypass security controls and reach endpoints.

## Attack Chain

1.  **Attacker creates malicious ClickOnce application**: Attacker develops a malicious application (e.g., info-stealer, backdoor, ransomware) and packages it using ClickOnce technology, generating the required deployment manifests (`.application`, `.manifest`) and application files.
2.  **Malicious hosting and delivery**: The attacker hosts the malicious ClickOnce deployment files on a compromised or attacker-controlled web server. They then distribute a link to the `.application` file via phishing emails, instant messages, or compromised websites, enticing victims to click.
3.  **Initial Access / User Interaction**: A victim is lured into clicking the provided link, which triggers the download of the `.application` deployment manifest file to their local machine (e.g., Downloads folder).
4.  **ClickOnce Deployment Service Invocation**: Upon user execution of the downloaded `.application` file (e.g., by double-clicking it), the Windows ClickOnce Deployment Support Service (`dfsvc.exe`) is automatically launched by the operating system.
5.  **User Confirmation**: If the publisher's certificate for the malicious application is untrusted or invalid, the OS prompts the user with a security warning. The victim is socially engineered to bypass this warning and confirm the installation.
6.  **Application File Download and Execution**: `dfsvc.exe` proceeds to download the malicious application files (e.g., `.exe`, `.dll`) from the attacker-controlled server into the user's ClickOnce application cache (`%LOCALAPPDATA%\Apps\2.0`). The application is then automatically executed.
7.  **Persistence (Optional)**: If configured by the attacker (e.g., via the "available offline" option) and accepted by the user during the initial installation wizard, the malicious ClickOnce application may register itself for persistence, ensuring it runs upon system reboot or user login.
8.  **Impact**: The malicious application (e.g., infostealer, backdoor, ransomware) executes with the user's privileges, achieving the attacker's objectives such as data exfiltration, remote control, or system encryption.

## Impact

The abuse of ClickOnce technology allows threat actors to bypass traditional security measures and seamlessly deploy malware onto victim systems. If successful, this can lead to widespread infections, as the technology is designed for minimal user friction. The impact can range from data theft and system compromise (e.g., infostealers, remote access trojans) to full system encryption and extortion (e.g., ransomware). Organizations across all sectors are vulnerable, as the attack leverages a common Windows deployment mechanism, making it difficult for average users to differentiate between legitimate and malicious ClickOnce applications. The ease of deployment and potential for persistence make this a highly effective initial access and execution vector for adversaries.

## Recommendation

*   Enable comprehensive process creation logging (e.g., Sysmon Event ID 1) to capture executions of `dfsvc.exe` and processes running from the ClickOnce application cache.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment, paying close attention to `dfsvc.exe` invocations and processes originating from `AppData\Local\Apps\2.0`.
*   Implement application control policies (e.g., Windows Defender Application Control, AppLocker) to restrict execution of unsigned binaries or executables from non-standard locations, particularly user profile directories.
*   Educate users about the risks of clicking on untrusted links or running `.application` files from unknown sources, emphasizing the importance of verifying publisher identities during ClickOnce installation prompts.
