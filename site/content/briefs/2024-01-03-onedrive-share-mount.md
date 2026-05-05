---
title: OneDrive Share Mounted via Net Utility for Potential Data Exfiltration
slug: 2024-01-03-onedrive-share-mount
description: Adversaries may mount OneDrive shares as network drives using net.exe or net1.exe to stage, access, or exfiltrate data through cloud-hosted WebDAV paths, potentially bypassing traditional file share monitoring.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - data-exfiltration
  - onedrive
  - net.exe
vendors:
  - Microsoft
  - Splunk
products:
  - OneDrive
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_onedrive_share_mounted_via_net.yml
rules:
  - title: Detect OneDrive Share Mounting via Net Utility
    description: Detects the use of net.exe or net1.exe to mount a OneDrive share as a network drive, potentially indicating data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - process_creation
      - windows
  - title: Detect OneDrive Share Mounting via Net Utility - Parent Process
    description: Detects the use of net.exe or net1.exe to mount a OneDrive share as a network drive, focusing on suspicious parent processes.
    platform: sigma
    severity: low
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may abuse the legitimate `net.exe` or `net1.exe` utilities to mount OneDrive shares as network drives on compromised Windows systems. This technique allows them to leverage cloud-hosted WebDAV paths for staging, accessing, or exfiltrating sensitive data. By using OneDrive, attackers can potentially bypass traditional file share monitoring and data loss prevention (DLP) controls, blending malicious traffic with legitimate cloud service usage. This activity has been observed in environments where data exfiltration is a primary objective, as it provides a covert channel for moving data outside the organization. This is an anomaly that warrants investigation as legitimate users may also perform this task.

## Attack Chain

1. An attacker gains initial access to a Windows endpoint via phishing, exploitation of a vulnerability, or stolen credentials.
2. The attacker executes `net.exe` or `net1.exe` with specific parameters to mount a OneDrive share as a network drive. The command includes the `use` parameter and a URL pointing to `https://d.docs.live.net`.
3. The attacker authenticates to the OneDrive share, potentially using stolen credentials or tokens.
4. The attacker copies sensitive data to the mounted OneDrive share.
5. The data is synchronized to the attacker's OneDrive account, effectively exfiltrating it from the victim's network.
6. The attacker may remove the mounted drive using `net use` with the `/delete` option to remove traces of the activity.
7. The attacker covers their tracks by deleting relevant event logs or modifying timestamps.

## Impact

Successful exploitation allows attackers to exfiltrate sensitive data from the victim's environment via a trusted cloud service, potentially leading to financial loss, reputational damage, and legal liabilities. The use of OneDrive can make detection more challenging, as the network traffic is often whitelisted and may not trigger traditional DLP alerts. The number of potential victims is broad, affecting any organization that uses OneDrive and has vulnerable or compromised Windows endpoints.

## Recommendation

*   Deploy the Sigma rule `Detect OneDrive Share Mounting via Net Utility` to your SIEM to identify potential malicious use of `net.exe` or `net1.exe` (log source: process_creation).
*   Enable Sysmon process creation logging (Event ID 1) with command line arguments to capture the full `net.exe` commands used for mounting shares.
*   Monitor Windows Event Log Security (Event ID 4688) for process creation events involving `net.exe` or `net1.exe` with parameters indicative of mounting a OneDrive share.
*   Implement network monitoring to detect unusual traffic patterns to `https://d.docs.live.net` that may indicate data exfiltration to OneDrive.
*   Review and tune the Sigma rule, `Detect OneDrive Share Mounting via Net Utility` based on observed false positives in your environment.
