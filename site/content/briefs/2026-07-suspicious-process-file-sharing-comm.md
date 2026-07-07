---
title: Suspicious Process Communication to File Sharing Domains from Unusual Folders
slug: 2026-07-suspicious-process-file-sharing-comm
description: This brief details the detection of malicious processes executing from non-standard or temporary Windows directories that initiate network communication with public file-sharing or code repository domains, often indicative of data exfiltration or Command and Control (C2) activities by various threat actors.
date: "2026-07-03T15:07:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - exfiltration
  - command-and-control
  - windows
  - malware
  - detection-pattern
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Detects executables located in potentially suspicious directories initiating network connections towards file sharing domains.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: The network connections to file sharing domains can be used for exfiltrating data, as described in ransomware blogs and CISA alerts.
    confidence_band: high
references:
  - https://twitter.com/M_haggis/status/900741347035889665
  - https://twitter.com/M_haggis/status/1032799638213066752
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-hive-conti-avoslocker
  - https://www.cisa.gov/uscert/ncas/alerts/aa22-321a
  - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/exfil/Invoke-ExfilDataToGitHub.ps1
rules:
  - title: Network Communication Initiated To File Sharing Domains From Process Located In Suspicious Folder
    description: Detects executables located in potentially suspicious directories initiating network connections towards common public file sharing or code repository domains, often indicative of data exfiltration or C2.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - network_connection
      - windows
rules_count: 1
---

This threat brief focuses on a common tactic employed by various threat actors, including ransomware groups like Hive, Conti, and AvosLocker, to exfiltrate data or maintain Command and Control (C2) communication. The technique involves malicious executables launching from specific, often temporary or system-generated, directories on Windows systems, then establishing outbound network connections to well-known public file-sharing services or code hosting platforms. This behavior is a strong indicator of compromise, as legitimate applications rarely operate from these locations while simultaneously communicating with such domains for core functionality. Defenders should prioritize detecting such activity, as it often precedes significant data loss or further stages of an attack.

## Attack Chain

1.  **Initial Access**: An attacker gains initial access to a system, typically through phishing, exploitation of a vulnerability, or a compromised legitimate application.
2.  **Execution**: A malicious payload is executed on the compromised system, often dropped and launched from a non-standard or temporary location such as `$Recycle.bin`, `Temp`, `Users\Public`, or `Windows\Tasks`.
3.  **Persistence**: The malware may establish persistence by placing itself or a loader within these suspicious directories to ensure execution across reboots, potentially leveraging system utilities or scheduled tasks.
4.  **Command and Control (C2) Setup**: The malicious process, now running from an unusual path, initiates outbound network connections to domains associated with public file-sharing services or code repositories (e.g., `githubusercontent.com`, `mega.nz`, `anonfiles.com`).
5.  **Exfiltration/Payload Delivery**: These established connections are then leveraged to exfiltrate sensitive data from the compromised system or to download additional malicious components and commands from the attacker's infrastructure hosted on these public services.
6.  **Impact**: The successful exfiltration of data leads to data theft, potential regulatory fines, reputational damage, or further compromise of the organization's network and assets through additional malware deployment.

## Impact

The observed impact of this attack pattern includes significant data exfiltration, leading to intellectual property theft, exposure of sensitive customer or employee data, and compliance violations. Furthermore, these connections often facilitate the download of additional payloads, such as ransomware or other destructive malware, leading to system encryption, operational disruption, and high recovery costs. While specific victim counts are not tied to this generic detection pattern, it has been leveraged in numerous high-profile campaigns against organizations across all sectors, as highlighted by CISA alerts regarding ransomware groups like Hive, Conti, and AvosLocker, where similar exfiltration methods were observed.

## Recommendation

*   Deploy the Sigma rule `Network Communication Initiated To File Sharing Domains From Process Located In Suspicious Folder` to your SIEM and tune for your environment.
*   Ensure Sysmon network connection logging is enabled to capture `network_connection` events for the rule above.
*   Review the `falsepositives` section of the rule and baseline any legitimate executables that might operate from the specified suspicious directories.
*   Implement egress filtering at the network perimeter to restrict outbound connections to known malicious domains or to only allow necessary business-related file-sharing services.
