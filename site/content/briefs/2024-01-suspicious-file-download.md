---
title: Suspicious Download from File Sharing Website via LOLBins
slug: 2024-01-suspicious-file-download
description: Detection of suspicious downloads from file sharing and content delivery platforms using living-off-the-land binaries (LOLBins) to identify potential initial access, payload staging, or command and control activity.
date: "2024-01-05T15:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lolbin
  - file-sharing
  - cisco-nvm
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1197
    technique_name: Spearphishing Attachment
references:
  - https://twitter.com/jhencinski/status/1102695118455349248
  - https://isc.sans.edu/forums/diary/Investigating+Microsoft+BITS+Activity/23281/
  - https://www.virustotal.com/gui/domain/paste.ee/relations
  - https://www.cisa.gov/uscert/ncas/alerts/aa22-321a
  - https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/
iocs:
  - type: domain
    value: '*.githubusercontent.com*'
  - type: domain
    value: '*anonfiles.com*'
  - type: domain
    value: '*cdn.discordapp.com*'
  - type: domain
    value: '*ddns.net*'
  - type: domain
    value: '*dl.dropboxusercontent.com*'
  - type: domain
    value: '*ghostbin.co*'
  - type: domain
    value: '*glitch.me*'
  - type: domain
    value: '*gofile.io*'
  - type: domain
    value: '*hastebin.com*'
  - type: domain
    value: '*mediafire.com*'
  - type: domain
    value: '*mega.nz*'
  - type: domain
    value: '*onrender.com*'
  - type: domain
    value: '*pages.dev*'
  - type: domain
    value: '*paste.ee*'
  - type: domain
    value: '*pastetext.net*'
  - type: domain
    value: '*send.exploit.in*'
  - type: domain
    value: '*sendspace.com*'
  - type: domain
    value: '*storage.googleapis.com*'
  - type: domain
    value: '*storjshare.io*'
  - type: domain
    value: '*supabase.co*'
  - type: domain
    value: '*temp.sh*'
  - type: domain
    value: '*transfer.sh*'
  - type: domain
    value: '*trycloudflare.com*'
  - type: domain
    value: '*ufile.io*'
  - type: domain
    value: '*w3spaces.com*'
  - type: domain
    value: '*workers.dev*'
ioc_counts:
  domain: 26
rules:
  - title: Suspicious PowerShell Download from File Sharing Site
    description: Detects PowerShell downloading files from known file sharing domains.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1197
    data_sources:
      - network_connection
      - windows
  - title: CertUtil Download from File Sharing Site
    description: Detects certutil.exe downloading files from known file sharing domains.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1197
    data_sources:
      - network_connection
      - windows
  - title: BITSAdmin Download from File Sharing Site
    description: Detects bitsadmin.exe downloading files from known file sharing domains.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1197
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

This threat brief addresses the abuse of living-off-the-land binaries (LOLBins) to download malicious payloads from file-sharing websites. Attackers leverage tools like `curl.exe`, `certutil.exe`, `msiexec.exe`, `powershell.exe`, and `wmic.exe` to retrieve payloads from public hosting platforms such as GitHub, Discord CDN, Transfer.sh, or Pastebin. This activity often bypasses traditional security measures, blending malicious network traffic with legitimate system processes. The detection outlined here relies on Cisco Network Visibility Module logs to provide network flow activity with process context, including command-line arguments, process path, and parent process information. Identifying this behavior is crucial for preventing initial access, detecting payload staging, and uncovering command and control activities disguised as normal operations. This approach is especially relevant given the increasing sophistication of threat actors and their ability to mask malicious behavior within trusted system processes.

## Attack Chain

1.  Initial Access: The attacker gains initial access through an undisclosed method (e.g., compromised account, software vulnerability).
2.  LOLBin Execution: A living-off-the-land binary (e.g., `powershell.exe`, `curl.exe`) is executed on the compromised system.
3.  Download Attempt: The LOLBin is used to download a file from a public file-sharing service (e.g., `githubusercontent.com`, `pastebin.com`). The command line includes the URL of the hosted payload.
4.  Payload Staging: The downloaded file is saved to a temporary location on the system (e.g., `C:\Windows\Temp`).
5.  Execution: The downloaded file is executed. This could be a script (e.g., PowerShell, VBScript) or an executable.
6.  Persistence: The attacker establishes persistence by creating a scheduled task, modifying registry keys, or other methods.
7.  Lateral Movement: The attacker uses compromised credentials or exploits vulnerabilities to move laterally to other systems on the network.
8.  Objective Achieved: The attacker achieves their final objective, which could be data exfiltration, ransomware deployment, or other malicious activities.

## Impact

Successful exploitation can lead to initial access, payload staging, command and control, and ultimately data theft, system compromise, or ransomware deployment. The scope of impact can range from individual endpoints to entire networks, depending on the attacker's objectives and lateral movement capabilities. Given that LOLBins are commonly used system tools, detecting malicious use requires careful analysis of process execution and network connections. Failure to detect this activity can result in significant financial losses, reputational damage, and operational disruption. Recent campaigns, such as those attributed to Mint Sandstorm, highlight the risk of targeting high-profile individuals at universities and research organizations.

## Recommendation

*   Deploy the provided Sigma rules to detect suspicious downloads from file-sharing websites using LOLBins, ingesting Cisco NVM flow data.
*   Monitor network connections from LOLBins (`curl.exe`, `certutil.exe`, `msiexec.exe`, `powershell.exe`, `wmic.exe`) to the listed file-sharing domains in the IOC table.
*   Review and tune the `cisco_nvm___suspicious_download_from_file_sharing_website_filter` macro to reduce false positives based on internal usage patterns.
*   Enable and monitor Cisco Network Visibility Module Flow Data to capture the required network and process context.
*   Ingest logs using the Splunk Add-on for Cisco Endpoint Security Analytics (CESA) as described in the "how_to_implement" section, to provide the necessary data for the Sigma rules.
