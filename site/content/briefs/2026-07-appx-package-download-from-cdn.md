---
title: Remote AppX Package Downloaded from File Sharing or CDN Domain
slug: 2026-07-appx-package-download-from-cdn
description: This brief details the detection of a malicious AppX package downloaded from untrusted file-sharing or CDN domains, a technique employed by threat actors like BazarLoader to deliver malware via abused Windows app mechanisms, potentially leading to system compromise and ransomware.
date: "2026-07-03T15:01:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - appx
  - malware
  - initial-access
  - stealth
  - windows
vendors:
  - Microsoft
products:
  - Windows AppX
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Detects an appx package that was added to the pipeline of the 'to be processed' packages which was downloaded from a file sharing or CDN domain.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1542
    technique_name: Pre-OS Boot
    evidence: The detection focuses on 'appx package that was added to the pipeline of the "to be processed" packages' and references articles detailing how 'malicious Windows apps' and 'Windows 10 apps mechanism' are abused for malware deployment, indicating the abuse of the AppX package manager system.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The Sophos reference 'BazarLoader call-me-back attack abuses Windows 10 apps mechanism' directly describes malspam (phishing) as the initial access vector leading to AppX deployment.
    confidence_band: high
references:
  - https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
  - https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting
  - https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_appx_downloaded_from_file_sharing_domains.yml
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
  - title: Remote AppX Package Downloaded from File Sharing or CDN Domain
    description: Detects an AppX package added to the processing pipeline that was downloaded from a remote file-sharing or CDN domain, indicating potential malware delivery.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - defense_evasion
      - stealth
    techniques:
      - T1105
      - T1542.003
    data_sources:
      - windows
      - appxdeployment-server
rules_count: 1
---

This threat brief focuses on the detection of Windows AppX packages that are downloaded from suspicious file-sharing or Content Delivery Network (CDN) domains. This technique is actively leveraged by various threat actors, including those behind BazarLoader campaigns, to bypass security controls and deliver malware. Starting as early as late 2021, adversaries have been observed abusing legitimate Windows mechanisms, such as the `AppInstaller.exe` utility and the `appxdeployment-server` service, to install malicious applications. The delivery typically involves phishing attacks leading to the download of `.appinstaller` or `.appx` files hosted on platforms like Discord's CDN, GitHub, or various file-sharing services. This method allows threat actors to distribute payloads discreetly, often bypassing traditional perimeter defenses and leading to initial access for further exploitation, data exfiltration, or ransomware deployment.

## Attack Chain

1.  **Initial Access**: A user receives a phishing email containing a malicious attachment, often a compressed archive (e.g., `.iso` or `.zip` file) impersonating a legitimate document or software update.
2.  **Execution - Malicious Loader**: The user opens the attachment, which contains a shortcut (`.lnk`) or a script that, when executed, triggers a download or execution process.
3.  **AppInstaller Abuse**: The malicious loader initiates `AppInstaller.exe` to process a specially crafted `.appinstaller` file, bypassing typical security prompts for unsigned applications.
4.  **Ingress Tool Transfer**: `AppInstaller.exe`, utilizing the `appxdeployment-server` service, downloads a malicious `.appx` or `.msix` package from a remote file-sharing or CDN domain (e.g., `cdn.discordapp.com`, `githubusercontent.com`, `storage.googleapis.com`).
5.  **Execution - Malware Deployment**: The downloaded AppX package is installed and then executes an embedded malicious payload, such as a loader for BazarLoader, IcedID, or other infostealers.
6.  **Command and Control (C2)**: The deployed malware establishes persistence on the compromised system and communicates with its command and control infrastructure to receive further instructions or download additional modules.
7.  **Impact**: The attacker proceeds with post-exploitation activities, including reconnaissance, privilege escalation, lateral movement, data exfiltration, or the deployment of ransomware.

## Impact

Successful exploitation allows threat actors to gain initial access to target systems, often bypassing standard application security measures and leading to significant consequences. Campaigns leveraging this technique, such as those deploying BazarLoader, have been observed across various sectors globally. The primary impact includes system compromise, execution of arbitrary code, installation of further malware (e.g., ransomware, infostealers, banking trojans), and potential data exfiltration. This can result in severe financial losses, operational disruption, and reputational damage for affected organizations.

## Recommendation

*   Deploy the Sigma rule "Remote AppX Package Downloaded from File Sharing or CDN Domain" to your SIEM system to detect suspicious AppX package downloads from untrusted domains.
*   Ensure `appxdeployment-server` logs are being collected from all Windows endpoints and forwarded to your SIEM for analysis.
*   Block the domains listed in the IOC section at your network perimeter (e.g., DNS resolver, firewall) to prevent access to known malicious AppX package hosting locations.
*   Implement strong email filtering and user awareness training to reduce the success rate of phishing attempts that serve as the initial access vector for such attacks.
*   Restrict the ability of non-administrative users to install applications via `AppInstaller.exe` or AppX packages where possible.
