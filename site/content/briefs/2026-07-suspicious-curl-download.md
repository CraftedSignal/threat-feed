---
title: Suspicious File Download From File Sharing Domain Via Curl.EXE
slug: 2026-07-suspicious-curl-download
description: A high-severity threat involves the abuse of `curl.exe` on Windows systems to download potentially malicious files from various public file-sharing and content delivery network (CDN) domains, a technique observed in campaigns by threat actors such as FIN7, leading to further system compromise.
date: "2026-07-03T15:10:57Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - FIN7
  - Carbon Spider
  - Sangria Tempest
tags:
  - curl
  - download
  - file-sharing
  - ingress-tool-transfer
  - windows
  - threat-hunting
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The rule detects `curl.exe` execution with specific command line arguments to download files.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: The rule identifies `curl.exe` downloading files (e.g., `.exe`, `.ps1`, `.dll`) from external, suspicious file-sharing domains.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: While the rule primarily detects ingress, `curl.exe` can also be used for exfiltration. The context of file-sharing domains makes it a suspicious channel for two-way communication.
    confidence_band: med
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_curl_download_susp_file_sharing_domains.yml
  - https://labs.withsecure.com/publications/fin7-target-veeam-servers
  - https://github.com/WithSecureLabs/iocs/blob/344203de742bb7e68bd56618f66d34be95a9f9fc/FIN7VEEAM/iocs.csv
iocs:
  - type: domain
    value: githubusercontent.com
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
    value: pixeldrain.com
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
  domain: 36
rules:
  - title: Suspicious File Download From File Sharing Domain Via Curl.EXE
    description: Detects potentially suspicious file download from public file-sharing or CDN domains using `curl.exe`.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1071.001
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Threat actors, including sophisticated groups like FIN7, are known to leverage legitimate system utilities such as `curl.exe` to download secondary stage payloads or malicious tools onto compromised Windows machines. This technique involves using `curl.exe` to connect to publicly accessible, but often abused, file-sharing services and CDNs (e.g., `githubusercontent.com`, `mega.nz`, `cdn.discordapp.com`) to retrieve executable binaries, scripts (`.ps1`, `.bat`), or dynamic link libraries (`.dll`). The activity is characterized by `curl.exe` command-line arguments specifying a download operation (e.g., `-O`, `--remote-name`, `--output`) and targeting specific file extensions. This method allows adversaries to bypass traditional perimeter defenses and introduce hostile code into a network, establishing persistence, escalating privileges, or preparing for data exfiltration and ransomware deployment. This behavior was highlighted in a detection rule originally published in May 2023 and updated in March 2026.

## Attack Chain

1.  **Initial Access**: An attacker gains initial access to a Windows system, possibly through spearphishing, exploiting a vulnerable service, or compromised credentials.
2.  **Execution of Initial Command**: The attacker establishes a foothold and executes an initial command-and-control mechanism or interactive shell (e.g., PowerShell, cmd.exe).
3.  **Ingress Tool Transfer**: `curl.exe` is launched from the command line with parameters to download additional malicious tools or payloads from an external source.
4.  **Suspicious Download**: `curl.exe` connects to a public file-sharing or content delivery network (CDN) domain (e.g., `githubusercontent.com`, `mega.nz`, `cdn.discordapp.com`) to retrieve a file.
5.  **Payload Staging**: The malicious file (e.g., `.exe`, `.ps1`, `.dll`, `.msi`) is saved to a specific location on the compromised system, often a temporary directory or a less scrutinized path.
6.  **Secondary Payload Execution**: The downloaded malicious payload is executed, leading to further compromise, such as establishing persistence, escalating privileges, deploying ransomware, or exfiltrating data.

## Impact

Successful exploitation results in the introduction and execution of arbitrary malicious code on the compromised system. This can lead to severe consequences including, but not limited to, full system compromise, data exfiltration, deployment of ransomware, establishment of persistent backdoors for long-term access, and lateral movement within the network. The specific impact depends on the nature of the downloaded payload, but the use of legitimate tools like `curl.exe` increases the likelihood of unnoticed initial compromise and enables sophisticated post-exploitation activities, potentially affecting multiple systems across an organization.

## Recommendation

*   Deploy the Sigma rule "Suspicious File Download From File Sharing Domain Via Curl.EXE" to your SIEM and tune for your environment to detect `curl.exe` activity.
*   Enable comprehensive process creation logging (e.g., via Sysmon) to ensure visibility into `curl.exe` executions and their command-line arguments.
*   Review network egress logs for connections to the file-sharing domains listed in the IOC section, especially when initiated by non-standard processes.
*   Implement application control policies to restrict unauthorized execution of `curl.exe` or its use to download specific file types from untrusted sources.
