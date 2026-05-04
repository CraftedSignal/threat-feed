---
title: Suspicious Execution from a Mounted Device
slug: 2024-01-suspicious-execution-mounted-device
description: Attackers may use mounted devices as a non-standard working directory to execute signed binaries or script interpreters, evading traditional defense mechanisms, particularly when launched via explorer.exe.
date: "2024-01-03T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
  - mounted-device
  - windows
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/
  - https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/
rules:
  - title: Suspicious Execution from Mounted Device
    description: Detects execution of common Windows binaries from mounted devices like USB drives.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Certutil Execution from Mounted Device
    description: Detects certutil execution from mounted device.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies suspicious execution of script interpreters or signed binaries from mounted devices in Windows environments. Attackers attempt to evade defenses by launching processes from non-standard directories, such as mounted devices. This technique can be employed following initial access via phishing or other means. The focus is on processes spawned by `explorer.exe` with a working directory on removable drives (D, E, F) and named `rundll32.exe`, `mshta.exe`, `powershell.exe`, `pwsh.exe`, `cmd.exe`, `regsvr32.exe`, `cscript.exe`, `wscript.exe`, `certutil.exe`, `bitsadmin.exe`, `msiexec.exe`, `wmic.exe`, `schtasks.exe`, or `msbuild.exe`. This behavior is anomalous and indicative of potential malicious activity. The rule originates from Elastic's detection rule set.

## Attack Chain

1. User unknowingly executes a malicious file (T1204.002) or opens a phishing email leading to drive-by compromise.
2. The malicious file is downloaded onto the system, potentially onto a mounted device such as a USB drive (D:\, E:\, or F:\).
3. The user interacts with the mounted device via `explorer.exe`, inadvertently triggering the execution of a malicious script or binary (TA0002).
4. The script interpreter (e.g., powershell.exe, cmd.exe) or a signed binary (e.g., mshta.exe, regsvr32.exe) is executed from the mounted device (T1059).
5. The process inherits the working directory from the mounted device, further masking its origin.
6. The script or binary performs malicious actions, such as downloading additional malware, establishing persistence, or exfiltrating data (TA0005).
7. The attacker leverages the trusted binary or interpreter to proxy execution of their malicious code (T1127, T1218).
8. The system is compromised, potentially leading to data theft, ransomware deployment, or lateral movement within the network.

## Impact

A successful attack of this nature can lead to the compromise of Windows systems. Attackers can evade traditional defenses, making detection more challenging. The impact can range from data theft and system compromise to lateral movement and ransomware deployment. Organizations may experience financial loss, reputational damage, and operational disruption if systems are successfully compromised using this technique.

## Recommendation

*   Enable Sysmon process creation logging (Event ID 1) to capture process execution events, including the working directory and parent process, which is essential for activating the rules below.
*   Deploy the "Suspicious Execution from Mounted Device" Sigma rule to your SIEM to detect potentially malicious processes being launched from unusual locations and tune for your environment.
*   Implement application control policies to restrict the execution of script interpreters and signed binaries from removable drives to mitigate the risk of this attack.
*   Educate users about the risks of executing files from untrusted sources, particularly from removable media, to prevent initial infection (T1204).
