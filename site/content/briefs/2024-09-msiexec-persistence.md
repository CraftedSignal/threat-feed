---
title: Persistence via Windows Installer (Msiexec)
slug: 2024-09-msiexec-persistence
description: Adversaries may establish persistence by abusing the Windows Installer (msiexec.exe) to create scheduled tasks or modify registry run keys, allowing for malicious code execution upon system startup or user logon.
date: "2024-09-05T14:17:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - defense-evasion
  - windows
vendors:
  - Microsoft
  - Adobe
  - HP
  - Intel
  - Acronis
  - Java
  - Citrix
  - OpenVPN
  - Veeam
  - Cisco
  - Epson
  - Jabra
  - VMware
  - ESET
  - iTunes
  - KeePassXC
  - Palo Alto Networks
  - PDF24
products:
  - Windows
  - Adobe Acrobat Update Task
  - Sure Click
  - Secure Access Client
  - CtxsDPS.exe
  - Openvpn-gui.exe
  - Veeam Endpoint Backup
  - Cisco Secure Client
  - Concentr.exe
  - Receiver
  - AnalyticsSrv.exe
  - Redirector.exe
  - Download Navigator
  - Jabra Direct
  - Vmware Workstation
  - Eset Security
  - iTunes
  - Keepassxc.exe
  - Globalprotect
  - Pdf24.exe
  - Vmware Tools
  - Teams
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_msi_installer_task_startup.toml
  - https://attack.mitre.org/techniques/T1053/
  - https://attack.mitre.org/techniques/T1053/005/
  - https://attack.mitre.org/techniques/T1547/
  - https://attack.mitre.org/techniques/T1547/001/
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/007/
rules:
  - title: Msiexec Creating Scheduled Task
    description: Detects msiexec.exe creating a new scheduled task by monitoring file creation events in the Task Scheduler directory.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1053.005
      - T1218.007
    data_sources:
      - file_event
      - windows
  - title: Msiexec Modifying Registry Run Keys
    description: Detects msiexec.exe modifying registry run keys for persistence.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1218.007
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: Msiexec Creating Startup Folder Item
    description: Detects msiexec.exe creating files in startup folders for persistence.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1218.007
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 3
---

The Windows Installer (msiexec.exe) is a legitimate system tool used for installing, updating, and removing software on Windows systems. Adversaries can abuse msiexec.exe to establish persistence mechanisms by creating malicious scheduled tasks or modifying registry run keys. This allows them to execute arbitrary code during system startup or user logon. This technique is attractive to attackers due to msiexec.exe being a trusted Windows binary, potentially evading detection by security solutions that focus on flagging unknown or suspicious processes. The use of msiexec.exe for persistence can be difficult to detect without specific monitoring rules, as it is a common and legitimate system process. This activity can be observed across various Windows versions and is frequently integrated into automated attack frameworks and scripts.

## Attack Chain

1. An attacker gains initial access to a compromised system, potentially through phishing, exploitation of a vulnerability, or stolen credentials.
2. The attacker leverages msiexec.exe to create a new scheduled task using the `schtasks.exe` command, setting it to execute a malicious script or binary.
3. Alternatively, the attacker uses msiexec.exe in conjunction with `reg.exe` or PowerShell to modify registry keys under `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` or `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, adding a pointer to their malicious executable.
4. The created scheduled task or registry entry points to a malicious payload, such as a reverse shell or a downloader.
5. The system is restarted, or the user logs on, triggering the execution of the newly created scheduled task or the malicious binary through the modified registry run key.
6. The malicious payload executes, establishing a persistent foothold for the attacker on the compromised system.
7. The attacker can now perform further actions, such as data exfiltration, lateral movement, or deployment of ransomware.

## Impact

Successful exploitation allows the adversary to maintain persistent access to the compromised system. This can lead to data theft, system compromise, deployment of ransomware, or use of the system as a staging point for further attacks within the network. A single compromised system can be used to pivot and compromise additional systems, leading to a widespread security breach. The impact can include financial losses, reputational damage, and disruption of business operations.

## Recommendation

*   Monitor process creation events for msiexec.exe spawning `schtasks.exe` or `reg.exe` to create scheduled tasks or modify registry run keys (reference: rules in this brief).
*   Implement and tune the Sigma rules provided in this brief to detect suspicious msiexec.exe activity related to persistence mechanisms.
*   Review and audit existing scheduled tasks and registry run keys for any suspicious entries or anomalies.
*   Enable file integrity monitoring (FIM) on critical system directories, including the Windows Task Scheduler directory and registry run key locations (reference: event.category == "file" and file.path ... and event.category == "registry" and registry.path ... in the rule query).
*   Implement application control policies to restrict the execution of unauthorized or unknown executables (reference: rule query).
