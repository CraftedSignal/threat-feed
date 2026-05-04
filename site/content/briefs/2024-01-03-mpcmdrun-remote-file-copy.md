---
title: MpCmdRun.exe Used for Remote File Download
slug: 2024-01-03-mpcmdrun-remote-file-copy
description: Attackers are abusing the Windows Defender MpCmdRun.exe utility to download remote files, potentially delivering malware or offensive tools into compromised systems.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - ingress-tool-transfer
  - windows
  - mpcmdrun
vendors:
  - Microsoft
products:
  - Windows Defender
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
references:
  - https://twitter.com/mohammadaskar2/status/1301263551638761477
  - https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-can-ironically-be-used-to-download-malware/
rules:
  - title: MpCmdRun Remote File Download
    description: Detects the use of MpCmdRun.exe to download remote files.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows
  - title: MpCmdRun Alternate File Name Remote File Download
    description: Detects the use of MpCmdRun.exe (identified by original filename) to download remote files.
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

Attackers are leveraging the built-in Windows Defender command-line utility, `MpCmdRun.exe`, to download files from remote locations. This technique allows attackers to bypass traditional download restrictions and blend in with legitimate system activity. The `MpCmdRun.exe` utility is normally used to manage Windows Defender settings and perform tasks such as signature updates and scans. However, its `-DownloadFile` parameter can be abused to download arbitrary files from a specified URL. This activity was first publicly reported around September 2020. Defenders should monitor for unusual usage patterns of `MpCmdRun.exe`, especially those involving command-line arguments related to file downloads from external sources.

## Attack Chain

1. An attacker gains initial access to a target system through an unrelated vulnerability or existing compromise.
2. The attacker uses `MpCmdRun.exe` to download a file from a remote server. The command includes arguments like `-DownloadFile`, `-url`, and `-path` to specify the download location and save path.
3. The downloaded file is saved to a location on the compromised system.
4. The attacker executes the downloaded file. This could be a malicious executable, a script, or a configuration file.
5. The executed file performs further malicious actions on the system, such as establishing persistence, escalating privileges, or deploying additional payloads.
6. The attacker uses the compromised system as a foothold to move laterally within the network, compromising other systems and resources.
7. The attacker achieves their ultimate objective, such as data exfiltration, ransomware deployment, or disruption of services.

## Impact

Successful exploitation allows attackers to introduce arbitrary malicious code into the system, potentially leading to a wide range of adverse effects, including data theft, system compromise, and disruption of operations. While individual cases may be limited in scope, widespread exploitation could impact numerous organizations, resulting in significant financial losses and reputational damage. The use of a trusted system utility makes this technique harder to detect using traditional methods.

## Recommendation

*   Deploy the Sigma rule `MpCmdRun Remote File Download` to your SIEM to detect the malicious use of `MpCmdRun.exe` for downloading files.
*   Enable Sysmon process creation logging with command-line arguments to provide the necessary data for the Sigma rule to function.
*   Review historical process execution logs for instances of `MpCmdRun.exe` being used with the `-DownloadFile` parameter.
*   Implement application control policies to restrict the execution of unsigned or untrusted executables downloaded by `MpCmdRun.exe`.
