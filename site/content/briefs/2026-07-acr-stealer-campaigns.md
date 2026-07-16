---
title: ACR Stealer Campaigns Use ClickFix Lures, WebDAV, and Steganography for Credential Theft
slug: 2026-07-acr-stealer-campaigns
description: Microsoft Defender Experts observed increased ACR Stealer activity from late April to mid-June 2026, using ClickFix social engineering lures in two distinct campaigns to steal browser credentials, authentication tokens, and sensitive documents from enterprise environments via WebDAV-based Python loaders or MSHTA-initiated PowerShell with steganography.
date: "2026-07-16T23:26:05Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - ACR Stealer
tags:
  - infostealer
  - malware-as-a-service
  - social-engineering
  - webdav
  - powershell
  - steganography
  - credential-theft
  - data-exfiltration
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: These campaigns are successfully using ClickFix lures to steal browser credentials, authentication tokens, and sensitive documents from enterprise environments.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: a ClickFix social engineering technique that tricks targets into running the threat actor’s command
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The command subsequently invokes rundll32.exe to load a DLL from a remote WebDAV share accessed over HTTPS.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: the malware establishes communication with threat actor-controlled infrastructure and executes a heavily obfuscated PowerShell script.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: a ClickFix prompt... instructs the target user to run a command that launches cmd.exe.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Establishes persistence through a hidden scheduled task disguised as a legitimate software update, ensuring execution at user sign-in.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Establishes persistence through a hidden scheduled task disguised as a legitimate software update, ensuring execution at user sign-in.
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: executes a heavily obfuscated PowerShell script. The script employs excessive arithmetic no-ops, dead loops, fake control flow, and randomized variable names to hinder static analysis and evade signature-based detection.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: a deceptive directory under %LocalAppData%\Temp (for example, LogiOptionsPlus).
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: clears PowerShell command history to reduce forensic visibility.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: Copies timestamps from a trusted Windows binary (notepad.exe) to the deployed files
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: Establishes persistence through a hidden scheduled task
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: steal browser credentials, authentication tokens, and sensitive documents
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: stealing browser credentials, authentication tokens, and sensitive documents
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: stealing browser credentials, authentication tokens, and sensitive documents
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: blockchain-backed dead-drop command-and-control (C2) resolution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Downloads a ZIP-packaged payload from a remote server
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: stealing browser credentials, authentication tokens, and sensitive documents for exfiltration.
    confidence_band: high
references:
  - https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/
rules:
  - title: Detect ACR Stealer Rundll32 WebDAV Payload Execution
    description: Detects rundll32.exe loading a DLL directly from a remote WebDAV share over HTTPS, a common initial execution method for ACR Stealer.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218.011
    data_sources:
      - process_creation
      - windows
  - title: Detect ACR Stealer Python Loader from Temp Directory
    description: Detects suspicious execution of pythonw.exe from the user's Local AppData temporary directory, a common stage for ACR Stealer's Python-based loader.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.006
      - T1564.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

From late April to mid-June 2026, Microsoft Defender Experts identified a surge in ACR Stealer activity impacting customer environments. ACR Stealer, an information-stealing malware offered via a malware-as-a-service (MaaS) model and reportedly a rebrand of Amatera Stealer, employs "ClickFix" social engineering lures to trick users into executing malicious commands. Two primary campaigns were observed: one utilizing WebDAV-delivered payloads, staged PowerShell, Python-based loaders, and blockchain-backed command-and-control (C2); the other adopting a fileless approach with MSHTA, obfuscated PowerShell, and steganography for in-memory execution. Both campaigns share the common objective of stealing browser credentials, session tokens, authentication artifacts, and sensitive enterprise documents. Successful compromise can lead to account takeover, unauthorized access to cloud resources, and subsequent intrusion activities.

## Attack Chain

1. **Initial Access via ClickFix Lure**: Users are tricked by social engineering (e.g., malvertising, SEO poisoning) through a "ClickFix" prompt to execute a threat actor-provided command.
2. **Remote DLL Execution via `cmd.exe` and `rundll32.exe`**: The user-executed command initiates `cmd.exe`, which then calls `rundll32.exe` to load and execute a malicious DLL directly from a remote WebDAV share over HTTPS. Attackers may use `pushd` to map the remote share locally and `conhost.exe -headless` for stealth.
3. **Staged PowerShell Loader Execution**: The loaded DLL communicates with C2 infrastructure and executes a heavily obfuscated PowerShell script, which employs arithmetic no-ops, dead loops, and randomized variable names for evasion.
4. **Payload Download and Staging**: The PowerShell script downloads a ZIP-packaged payload from a remote server, extracting it into a deceptive directory (e.g., `LogiOptionsPlus`) under `%LocalAppData%\Temp`.
5. **Python-based Loader Launch**: A bundled `pythonw.exe` instance is used to launch a Python script from the extracted payload, thereby avoiding console window display.
6. **Persistence Establishment**: A hidden scheduled task, disguised as a legitimate software update, is created to ensure the malware's execution at user sign-in.
7. **Defense Evasion**: The malware copies timestamps from a legitimate Windows binary (`notepad.exe`) to its deployed files and clears PowerShell command history to hinder forensic analysis.
8. **Information Theft and Exfiltration**: The Python-based loader collects browser-stored credentials, authentication tokens, and sensitive documents, which are then prepared for exfiltration, potentially to blockchain C2 infrastructure.

## Impact

Successful ACR Stealer infections lead to significant data breaches within targeted enterprises. Victims face the exposure of browser credentials, session tokens, authentication artifacts, and other sensitive documents, which can be leveraged for account compromise, unauthorized access to cloud resources, and further intrusive activities within the network. The scope of targeting is broad, impacting various enterprise customer environments observed by Microsoft Defender Experts. The theft of such critical data facilitates lateral movement and potentially expands the attacker's foothold, leading to more severe and widespread compromises.

## Recommendation

* Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious `rundll32.exe` and `pythonw.exe` activity.
* Enable Sysmon process creation logging to capture `cmd.exe`, `rundll32.exe`, and `pythonw.exe` executions for analysis.
* Monitor for `rundll32.exe` processes executing DLLs directly from remote network shares, especially WebDAV shares, as identified in `Detect ACR Stealer Rundll32 WebDAV Payload Execution`.
* Monitor for `pythonw.exe` processes launching from temporary user application data directories (e.g., `%LocalAppData%\Temp\`) when the parent process is suspicious, as described in `Detect ACR Stealer Python Loader from Temp Directory`.
* Implement robust endpoint detection and response (EDR) solutions, such as Microsoft Defender for Endpoint, to detect living-off-the-land binaries, obfuscated PowerShell, and scheduled task persistence.
* Educate users on "ClickFix" and other social engineering lures to prevent initial execution of malicious commands.
