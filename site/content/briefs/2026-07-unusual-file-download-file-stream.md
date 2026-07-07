---
title: Unusual File Download From File Sharing Websites - File Stream
slug: 2026-07-unusual-file-download-file-stream
description: This brief details the detection of suspicious file types (batch, command, PowerShell scripts) downloaded from well-known public file and paste sharing domains, leveraging the `Zone.Identifier` Alternate Data Stream to signal potential malware delivery or covert data transfer, which could lead to system compromise and data exfiltration.
date: "2026-07-03T15:05:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - file-download
  - delivery
  - windows
  - defense-evasion
  - command-and-control
  - execution
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: Detects the presence of an Alternate Data Stream (ADS) Zone.Identifier on downloaded files, indicating the file originated from the internet, a common method attackers may manipulate to evade scrutiny.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Detects file downloads from well-known public file and paste sharing domains, which attackers often use for payload delivery or as part of their command and control infrastructure leveraging common web protocols.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The rule specifically targets downloads of files with `.bat`, `.cmd`, or `.ps1` extensions, indicating an attacker's intent to execute commands or scripts via a command and scripting interpreter on the target system.
    confidence_band: high
references:
  - https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90015
  - https://www.cisa.gov/uscert/ncas/alerts/aa22-321a
  - https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_file_sharing_domains_download_unusual_extension.yml
rules:
  - title: Unusual File Download From File Sharing Websites - File Stream
    description: Detects the download of suspicious file types (batch, command, PowerShell scripts) from well-known public file and paste sharing domains by monitoring the creation of Zone.Identifier Alternate Data Streams.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1071.001
      - T1564.004
    data_sources:
      - create_stream_hash
      - windows
rules_count: 1
---

This threat brief focuses on a behavioral detection designed to identify suspicious file downloads from public file and paste sharing websites. Attackers frequently leverage legitimate services like GitHub, Mega.nz, Pastebin, or Discord to host malicious payloads, command and control configurations, or exfiltrated data. This method allows them to bypass traditional network filtering and evade detection by blending in with legitimate traffic. The detection specifically targets files with common scripting extensions (`.bat`, `.cmd`, `.ps1`) that also carry the `Zone.Identifier` Alternate Data Stream, a Windows mechanism indicating a file's origin from the internet. The presence of this stream on executable or script files downloaded from untrusted public sources is a strong indicator of potential malicious activity, such as the delivery of initial access payloads, second-stage malware, or tools for persistence. Defenders should be aware that such downloads are often precursors to full system compromise.

## Attack Chain

1.  Initial access is achieved, potentially via a phishing campaign, compromised legitimate software, or exploitation of a vulnerable internet-facing application, granting the attacker initial execution capabilities on a target system.
2.  The attacker utilizes the initial foothold to stage a secondary payload download, often calling out to publicly available and trusted-looking file or paste-sharing services to host the malicious artifact.
3.  A malicious script or binary on the compromised system initiates a download of a file from a well-known public file-sharing domain (e.g., `githubusercontent.com`, `mega.nz`, `cdn.discordapp.com`).
4.  The downloaded file arrives with a suspicious scripting extension (such as `.bat`, `.cmd`, or `.ps1`) and inherently creates an Alternate Data Stream (ADS) named `Zone.Identifier`, marking its origin from the internet.
5.  The system records the creation of this file and its associated `Zone.Identifier` stream, indicating an external download of potentially executable content.
6.  The attacker then attempts to execute this downloaded script using a command and scripting interpreter (e.g., PowerShell, cmd.exe), often through a user interaction or an automated mechanism.
7.  Successful execution leads to the establishment of persistent access, full command and control capabilities, data exfiltration to attacker-controlled infrastructure, or the deployment of further malware such as ransomware.

## Impact

If malicious script files downloaded from public file-sharing domains are executed, organizations face significant risks including full system compromise, network lateral movement, and data exfiltration. Attackers can leverage these initial access points to deploy ransomware, steal sensitive information, or disrupt critical operations. The use of legitimate services makes these attacks harder to detect at the network perimeter, increasing the likelihood of successful execution and subsequent damage. The impact often includes financial loss due to business disruption, regulatory fines, and reputational damage. While no specific victim numbers are available for this generic detection, such techniques are widely employed across various sectors by numerous threat actors.

## Recommendation

*   Deploy the Sigma rule "Unusual File Download From File Sharing Websites - File Stream" to your SIEM and tune for your environment to detect suspicious file downloads.
*   Ensure Sysmon `EventID 15` (FileStreamCreated) logging is enabled and collected for all Windows endpoints to activate the detection rule.
*   Investigate alerts generated by the rule for `TargetFilename` values ending in `:Zone` combined with suspicious extensions (`.bat`, `.cmd`, `.ps1`) originating from `Contents` containing known file-sharing domains.
*   Educate users on the risks of downloading and executing files from untrusted sources, even if hosted on legitimate platforms, as these are frequently used in phishing and malware delivery schemes.
