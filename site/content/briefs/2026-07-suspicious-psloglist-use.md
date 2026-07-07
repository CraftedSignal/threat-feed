---
title: Suspicious Use of PsLogList for Event Log Discovery and Evasion
slug: 2026-07-suspicious-psloglist-use
description: Adversaries are leveraging the legitimate Sysinternals utility PsLogList to perform account and system discovery by dumping Windows event logs, and for defense evasion by clearing or exporting these logs, increasing their ability to operate undetected and further compromise systems.
date: "2026-07-03T14:40:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - sysinternals
  - discovery
  - defense-evasion
  - account-discovery
  - log-clearing
  - windows
vendors:
  - Microsoft
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: Detects usage of the PsLogList utility to dump event log in order to extract admin accounts and perform account discovery
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: Detects usage of the PsLogList utility to dump event log in order to extract admin accounts and perform account discovery
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
    evidence: Detects usage of the PsLogList utility to ... delete events logs [using the `-c` flag]
    confidence_band: high
references:
  - https://research.nccgroup.com/2021/01/12/abusing-cloud-services-to-fly-under-the-radar/
  - https://www.cybereason.com/blog/deadringer-exposing-chinese-threat-actors-targeting-major-telcos
  - https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Sysinternals/PsLogList
  - https://twitter.com/EricaZelic/status/1614075109827874817
rules:
  - title: Suspicious Use of PsLogList
    description: Detects usage of the PsLogList utility to dump event logs in order to extract admin accounts, perform account discovery, or delete events logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - discovery
    techniques:
      - T1070.004
      - T1087
      - T1087.001
      - T1087.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

This brief details the suspicious use of PsLogList, a legitimate command-line utility from the Sysinternals suite, which is being abused by adversaries for both discovery and defense evasion. PsLogList allows administrators to view, filter, dump, and clear Windows event logs. Attackers exploit this functionality to extract sensitive information, such as admin accounts from security logs, facilitating further account discovery and privilege escalation. Additionally, its capability to clear event logs (`-c` flag) or export them (`-g` flag) is utilized to hinder forensic analysis and remove traces of malicious activity. This activity has been observed in campaigns by advanced threat actors, including those targeting major telecommunications companies, highlighting its role in post-compromise reconnaissance and operational security. Detection focuses on command-line arguments indicative of malicious intent rather than legitimate administrative use.

## Attack Chain

1.  **Initial Access**: Adversaries gain initial access to a target system through various means, such as exploiting a public-facing application, phishing, or stolen credentials.
2.  **Tool Staging**: The PsLogList utility (`psloglist.exe` or `psloglist64.exe`) is downloaded and staged on the compromised system, often in a non-standard directory.
3.  **Event Log Discovery (Account Enumeration)**: The adversary executes `psloglist.exe` with parameters like `security`, `application`, or `system` to dump relevant event logs, specifically searching for local or domain administrator accounts. Example: `psloglist security -d 1000`
4.  **Event Log Export**: PsLogList is executed with the `-g` flag to export event logs to a file (`.evt`), allowing for offline analysis without triggering host-based detection. Example: `psloglist security -g C:\temp\security.evt`
5.  **Defense Evasion (Log Clearing)**: The adversary uses `psloglist.exe` with the `-c` flag to clear specific event logs, such as the security log, to remove evidence of their presence and actions. Example: `psloglist security -c`
6.  **Information Exploitation**: Information gathered from the event logs (e.g., admin accounts, system details) is then used to facilitate lateral movement, privilege escalation, or further targeting within the network.
7.  **Impact**: Subsequent actions, such as data exfiltration or deploying ransomware, are executed, leveraging the gained privileges and evaded defenses.

## Impact

The abuse of PsLogList for event log discovery and defense evasion has a significant impact on an organization's security posture. Successful exploitation allows adversaries to gain a deeper understanding of the victim environment, identify valuable accounts for privilege escalation or lateral movement, and systematically erase their tracks. This directly hampers incident response efforts by removing crucial forensic evidence, making attribution and scope determination extremely difficult. In targeted attacks, such as those against major telcos by Chinese threat actors, this can lead to sustained compromise, intellectual property theft, and disruption of critical infrastructure.

## Recommendation

*   Deploy the `Suspicious Use of PsLogList` Sigma rule to your SIEM to detect command-line activity associated with this tool.
*   Ensure process creation logging (e.g., via Sysmon) is enabled and configured to capture full command-line arguments to activate the rules above.
*   Regularly review administrative use of PsLogList to establish a baseline of legitimate activity and tune detections to reduce false positives.
*   Investigate any instances where PsLogList is executed with parameters for clearing (`-c`) or exporting (`-g`) event logs, especially if originating from non-administrative contexts or user accounts.
