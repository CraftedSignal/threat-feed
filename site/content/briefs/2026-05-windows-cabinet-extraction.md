---
title: Windows Cabinet File Extraction via Expand.exe
slug: 2026-05-windows-cabinet-extraction
description: Detection of expand.exe being used to extract Microsoft Cabinet (CAB) archives, specifically when extracting to C:\ProgramData or similar staging locations, potentially indicating ingress tool transfer and payload staging by threat actors like APT37.
date: "2026-05-28T18:01:21Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - APT37
tags:
  - cabinet_extraction
  - expand.exe
  - apt37
  - windows
  - endpoint
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1105
    technique_name: Ingress Tool Transfer
references:
  - https://www.zscaler.com/blogs/security-research/apt37-targets-windows-rust-backdoor-and-python-loader
rules:
  - title: Detect Windows Cabinet File Extraction to ProgramData
    description: Detects the execution of expand.exe to extract cabinet files into C:\ProgramData or similar locations, which may indicate malicious payload staging.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows
  - title: Detect Cabinet File Extraction via Expand - Suspicious Parent Process
    description: Detects expand.exe being used to extract cabinet files, with a suspicious parent process like certutil or powershell, which may indicate initial access via tool transfer.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection focuses on identifying the use of `expand.exe`, a legitimate Windows utility, for the extraction of Microsoft Cabinet (CAB) archives into suspicious directories. Threat actors may use this technique to bypass security controls and stage malicious payloads. The activity is considered suspicious when the destination path is `C:\\ProgramData` or other similar staging locations. In particular, APT37 has been observed using this method, expanding CAB files (e.g., wonder.cab) into `C:\\ProgramData` before establishing persistence and executing the payload. The technique is a strong indicator of initial access via tool transfer and subsequent payload staging, allowing attackers to execute further malicious actions on the compromised system. This detection is based on behavioral analysis, specifically focusing on the combination of `expand.exe` execution and the extraction path.

## Attack Chain

1. An attacker gains initial access to a system (e.g., through phishing).
2. The attacker transfers a malicious CAB archive (e.g., wonder.cab) to the compromised system, potentially using tools like `certutil.exe` or `bitsadmin.exe`.
3. The attacker uses `expand.exe` with the `-F:*` or `/F:*` option to extract the contents of the CAB archive.
4. The destination directory for the extraction is set to `C:\\ProgramData` or a similar staging location.
5. The extracted files may include malicious executables, scripts, or configuration files.
6. The attacker establishes persistence by creating a scheduled task or registry entry that points to the extracted malicious executable.
7. The malicious executable is launched, initiating further stages of the attack, such as establishing a command-and-control (C2) connection.
8. The attacker achieves their final objective, which may include data exfiltration, ransomware deployment, or lateral movement within the network.

## Impact

Successful exploitation can lead to the compromise of endpoints and subsequent data theft, ransomware deployment, or lateral movement within the network. The use of `expand.exe` for malicious purposes can bypass traditional security measures, as it is a legitimate Windows utility. The impact is heightened when threat actors like APT37 employ this technique to deliver and stage sophisticated malware. This activity can affect any Windows endpoint within an organization, potentially leading to significant operational disruption and financial losses.

## Recommendation

*   Enable process creation logging with full command-line auditing (e.g., Sysmon Event ID 1 or Windows Event Log Security 4688) to capture `expand.exe` arguments, including `/F:*` or `-F:*`, and destination paths, as described in the **How To Implement** section.
*   Deploy the provided Sigma rule, **Detect Windows Cabinet File Extraction to ProgramData**, to your SIEM and tune it based on your environment. Pay special attention to potential false positives, as outlined in the **Known False Positives** section.
*   Monitor parent processes of `expand.exe` to identify potential ingress tools or delivery mechanisms (e.g., `certutil.exe`, `powershell.exe`, `bitsadmin.exe`).
*   Investigate any instances of `expand.exe` being executed with a destination path of `C:\\ProgramData` or similar staging directories.
*   Review and update endpoint detection and response (EDR) policies to specifically detect and alert on `expand.exe` being used to extract CAB archives into suspicious locations.
