---
title: Suspicious Download From File-Sharing Website Via Bitsadmin
slug: 2026-07-suspicious-download-via-bitsadmin
description: This threat brief details the detection of adversaries leveraging the legitimate Windows Background Intelligent Transfer Service (BITSAdmin) utility to download malicious payloads from suspicious file-sharing and cloud storage domains, a technique commonly employed by ransomware groups and APTs for ingress tool transfer and stealthy execution.
date: "2026-07-03T15:08:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - living-off-the-land
  - lolbas
  - payload-delivery
  - ingress-tool-transfer
  - command-and-control
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1197
    technique_name: BITS Jobs
    evidence: BITSAdmin can be used to create background intelligent transfer service jobs, which can persist across reboots, and download files from remote servers.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The `bitsadmin.exe` utility is executed via command line.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: The detection rule explicitly aims to detect usage of `bitsadmin` downloading a file from a suspicious domain, which is a direct method of ingress tool transfer.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: The `bitsadmin.exe` utility is executed via the command line, often through `cmd.exe` or `powershell.exe`.
    confidence_band: high
references:
  - https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
  - https://isc.sans.edu/diary/22264
  - https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-hive-conti-avoslocker
  - https://www.cisa.gov/uscert/ncas/alerts/aa22-321a
  - https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/
iocs:
  - type: domain
    value: .githubusercontent.com
  - type: domain
    value: 0x0.st
  - type: domain
    value: anonfiles.com
  - type: domain
    value: bashupload.com
  - type: domain
    value: cdn.discordapp.com
  - type: domain
    value: chunk.io
  - type: domain
    value: ddns.net
  - type: domain
    value: dl.dropboxusercontent.com
  - type: domain
    value: ghostbin.co
  - type: domain
    value: github.com
  - type: domain
    value: glitch.me
  - type: domain
    value: gofile.io
  - type: domain
    value: hastebin.com
  - type: domain
    value: mediafire.com
  - type: domain
    value: mega.nz
  - type: domain
    value: onrender.com
  - type: domain
    value: pages.dev
  - type: domain
    value: paste.ee
  - type: domain
    value: pastebin.com
  - type: domain
    value: pastebin.pl
  - type: domain
    value: pastetext.net
  - type: domain
    value: privatlab.com
  - type: domain
    value: privatlab.net
  - type: domain
    value: send.exploit.in
  - type: domain
    value: sendspace.com
  - type: domain
    value: storage.googleapis.com
  - type: domain
    value: storjshare.io
  - type: domain
    value: supabase.co
  - type: domain
    value: temp.sh
  - type: domain
    value: transfer.sh
  - type: domain
    value: trycloudflare.com
  - type: domain
    value: ufile.io
  - type: domain
    value: w3spaces.com
  - type: domain
    value: workers.dev
  - type: domain
    value: x0.at
ioc_counts:
  domain: 35
rules:
  - title: Detect Suspicious Download From File-Sharing Website Via Bitsadmin
    description: Detects usage of the built-in Windows `bitsadmin.exe` utility downloading files from suspicious file-sharing or cloud storage domains, a common technique for ingress tool transfer.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
      - persistence
      - s0190
    techniques:
      - T1059
      - T1105
      - T1197
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Adversaries frequently abuse the Windows BITSAdmin utility to download additional tools and payloads, bypassing traditional security controls due to its nature as a legitimate, signed Microsoft binary. This technique allows attackers to perform ingress tool transfer (MITRE ATT&CK T1105) from various file-sharing and cloud storage services like GitHub, Mega.nz, or Discord's CDN, making detection challenging. Observed in campaigns like Mint Sandstorm and by ransomware groups such as Hive, Conti, and AvosLocker, this method enables stealthy delivery of malware. The activity is particularly concerning when `bitsadmin.exe` initiates downloads from domains typically used for public file hosting, indicating a likely attempt to fetch staged malicious components after initial compromise. Detecting this behavior is crucial for identifying early stages of compromise and preventing further attacker progression.

## Attack Chain

1.  **Initial Access**: Adversaries gain initial access, often via phishing campaigns delivering malicious documents or exploiting a vulnerable internet-facing service, leading to arbitrary code execution.
2.  **Execution**: A command interpreter (e.g., `cmd.exe` or `powershell.exe`) is executed with administrative privileges to launch subsequent commands.
3.  **Ingress Tool Transfer**: The `bitsadmin.exe` utility is invoked with parameters like `/transfer`, `/create`, or `/addfile` to initiate a background download.
4.  **Staging Payload**: `bitsadmin.exe` downloads a malicious executable, script, or DLL from a suspicious file-sharing or cloud storage domain (e.g., `dl.dropboxusercontent.com`, `cdn.discordapp.com`, `mega.nz`) to a temporary or public-facing directory on the compromised system.
5.  **Further Execution**: The newly downloaded malicious payload is then executed, often via another command or script, to establish persistence or escalate privileges.
6.  **Impact**: The execution of the payload leads to the final objective, which commonly includes deploying ransomware, exfiltrating sensitive data, or establishing long-term command and control within the victim's network.

## Impact

Successful exploitation of this technique can lead to severe consequences, as it facilitates the delivery of sophisticated malware, including ransomware, backdoors, and credential stealers. Organizations targeted by such attacks, particularly those in critical infrastructure sectors or government, face significant data loss, operational disruption, and financial repercussions. Campaigns like Mint Sandstorm have targeted high-profile individuals at universities and research organizations, indicating a focus on sensitive intellectual property. The use by ransomware groups such as Hive, Conti, and AvosLocker highlights the potential for widespread encryption of systems and extortion demands, resulting in costly recovery efforts and reputational damage for affected entities.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune for your environment to detect `bitsadmin.exe` downloading from suspicious domains.
*   Monitor `process_creation` logs for `bitsadmin.exe` execution and analyze command-line arguments for suspicious URLs.
*   Review network logs and proxy data for connections originating from `bitsadmin.exe` to the IOC domains listed below.
*   Implement application whitelisting to restrict `bitsadmin.exe` usage to only approved scenarios or accounts.
*   Educate users on phishing awareness, as this technique often follows an initial access gained through social engineering.
