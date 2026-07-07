---
title: Windows Autostart Persistence via Startup Folder
slug: 2026-07-windows-autostart-startup-folder
description: Adversaries commonly leverage file creation in the Windows `%startup%` folder (T1547.001) to establish persistence, ensuring malicious code executes automatically upon system boot or user logon, potentially leading to system compromise and unauthorized access.
date: "2026-07-03T13:09:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - execution
  - windows
  - malware
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The following analytic detects the creation of files in the Windows %startup% folder, a common persistence technique. ... adversaries often use the startup folder to ensure their malicious code executes automatically upon system boot or user logon.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: adversaries often use the startup folder to ensure their malicious code executes automatically upon system boot or user logon.
    confidence_band: med
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_boot_or_logon_autostart_execution_in_startup_folder.yml
  - https://attack.mitre.org/techniques/T1547/001/
  - https://attack.mitre.org/techniques/T1204/002/
  - https://www.fortinet.com/blog/threat-research/chaos-ransomware-variant-sides-with-russia
rules:
  - title: Detect Windows Autostart Persistence via Startup Folder
    description: Detects the creation of files in the Windows Startup folder, a common technique for establishing persistence upon system boot or user logon (T1547.001).
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1204.002
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

This threat brief details a common persistence technique where adversaries create malicious files within the Windows `%startup%` folder. This method, categorized under MITRE ATT&CK T1547.001 (Boot or Logon Autostart Execution: Startup Folder), ensures that attacker-controlled code automatically executes whenever the system boots or a user logs in. While the specific threat actor or delivery mechanism is not detailed in this particular intelligence, the technique is widely adopted by various malware families and adversaries, including those associated with XWorm and Chaos Ransomware campaigns. Detection of such activity is crucial as it signifies established foothold and continued unauthorized access, potentially leading to further system compromise and data exfiltration.

## Attack Chain

1. Initial Access is gained by the adversary through an unspecified method (e.g., phishing, exploit).
2. The adversary then executes a command or process to place a malicious executable or script (e.g., `malware.exe`, `script.vbs`, or a shortcut `.lnk` file) into the user's or system's Windows Startup folder. Common paths include `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` or `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`.
3. The malicious file is specifically crafted to serve as a persistence mechanism, often being a downloader, a remote access Trojan (RAT), or a component of ransomware.
4. Upon the next system boot or user logon, the Windows operating system enumerates the contents of the Startup folder and automatically launches the newly placed malicious file.
5. The automatically executed malicious code initiates its payload, which could involve establishing command and control (C2) communication, collecting system information, or dropping additional stages of malware.
6. This successful execution provides the adversary with sustained access to the compromised endpoint, allowing for continued malicious operations even after system restarts or user logoffs.

## Impact

If successful, the adversary gains persistent access to the compromised system, allowing for continued execution of malicious payloads. This can lead to severe consequences including, but not limited to, unauthorized access to sensitive data, installation of additional malware (e.g., ransomware, stealers, remote access Trojans as seen with XWorm and Chaos Ransomware), lateral movement within the network, and complete system compromise. The prolonged presence significantly increases the risk of data exfiltration and disruption of business operations.

## Recommendation

*   Deploy the Sigma rule "Detect Windows Autostart Persistence via Startup Folder" in this brief to your SIEM and tune for your environment.
*   Enable Sysmon Event ID 11 (FileCreate) logging on all Windows endpoints to ensure the necessary telemetry for this detection is collected.
*   Implement application whitelisting or strong execution policies to prevent unauthorized executables from running from the `%startup%` folder.
