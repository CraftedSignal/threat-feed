---
title: Windows Autostart Execution in Startup Folder for Persistence
slug: 2026-07-autostart-execution-startup-folder
description: Adversaries leverage the Windows %startup% folder to establish persistence by creating malicious files that execute automatically upon system boot or user logon, potentially leading to system compromise and unauthorized access.
date: "2026-07-24T09:05:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - autostart
  - windows
  - detection
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The following analytic detects the creation of files in the Windows %startup% folder, a common persistence technique. It leverages the Endpoint.Filesystem data model to identify file creation events in this specific directory.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_boot_or_logon_autostart_execution_in_startup_folder.yml
  - https://www.fortinet.com/blog/threat-research/chaos-ransomware-variant-sides-with-russia
rules:
  - title: Detect File Creation in Windows Startup Folder
    description: Detects the creation of new files within the Windows user-specific Startup folder, which is a common persistence mechanism used by malware to ensure execution upon system boot or user logon.
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

This brief details a common persistence technique where adversaries create or modify files within the Windows Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`) to ensure their malicious code or shortcuts execute automatically. This mechanism allows attackers to maintain unauthorized access to a system after an initial compromise, ensuring their tools or backdoors restart with the operating system or user session. The technique is frequently observed in various malware campaigns, including ransomware families like Chaos Ransomware and multiple stealer and RAT variants such as NjRAT, RedLine Stealer, and Quasar RAT, which use it to re-establish control. Detecting such activity is crucial for preventing long-term compromise, as sustained access can lead to data exfiltration, further system entanglement, and impact on sensitive information.

## Attack Chain

1. **Initial Compromise:** An attacker gains initial access to a target system through various means (e.g., spearphishing, exploiting a vulnerable service, or drive-by download).
2. **Malware Delivery:** The attacker delivers a payload, which could be an executable, script, or shortcut file.
3. **File Creation in Startup Folder:** The delivered payload or a component of it creates a file (e.g., `malicious.exe`, `script.vbs`, `shortcut.lnk`) in the `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` directory.
4. **System Reboot/User Logon:** The victim system is rebooted, or the user logs on to their account.
5. **Automatic Execution:** The operating system automatically executes the malicious file placed in the Startup folder.
6. **Persistence Established:** The malicious code runs, re-establishing the attacker's presence on the system. This could involve re-launching a command and control (C2) agent, re-infecting the system, or performing other malicious activities.
7. **Impact Continuation:** The attacker maintains unauthorized access, potentially leading to continued data exfiltration, further system compromise, or the deployment of additional malicious functionalities (e.g., ransomware encryption).

## Impact

The successful exploitation of this persistence mechanism can lead to severe consequences for an organization. Adversaries can maintain long-term unauthorized access to compromised systems, bypassing security measures and re-establishing control even after system restarts. This sustained presence enables attackers to exfiltrate sensitive data, deploy additional malware such as ransomware (e.g., Chaos Ransomware), or use the compromised host as a staging ground for lateral movement within the network. This technique has been observed in various malware campaigns, affecting multiple sectors by facilitating prolonged espionage, data theft, and destructive attacks.

## Recommendation

* Deploy the Sigma rule "Detect File Creation in Windows Startup Folder" to your SIEM to monitor for suspicious file creations.
* Enable Sysmon EventID 11 (FileCreate) logging on all Windows endpoints to ensure the necessary telemetry is collected for detection.
* Investigate any alerts from the "Detect File Creation in Windows Startup Folder" rule to determine if the activity is legitimate.
