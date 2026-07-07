---
title: Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE
slug: 2026-07-certutil-file-sharing-download
description: This brief details the use of the legitimate Windows utility `certutil.exe` by various threat actors to download malicious files from public file-sharing and code-hosting websites, facilitating further compromise and evasion on targeted systems.
date: "2026-07-03T15:09:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lolbin
  - windows
  - defense-evasion
  - ingress-tool-transfer
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: Detects the execution of certutil with certain flags that allow the utility to download files from file-sharing websites.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Detects the execution of certutil with certain flags that allow the utility to download files from file-sharing websites.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
  - https://forensicitguy.github.io/agenttesla-vba-certutil-download/
  - https://news.sophos.com/en-us/2021/04/13/compromised-exchange-server-hosting-cryptojacker-targeting-other-exchange-servers/
  - https://twitter.com/egre55/status/1087685529016193025
  - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
  - https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/
  - https://www.hexacorn.com/blog/2020/08/23/certutil-one-more-gui-lolbin
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
  - title: Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE
    description: Detects the execution of certutil with specific flags used to download files from common file-sharing or code-hosting websites, a technique often used for ingress tool transfer.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - defense_evasion
    techniques:
      - T1027
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Threat actors frequently abuse legitimate Windows binaries (Living Off the Land Binaries, or LOLBINs) to evade detection and perform malicious activities, a technique known as "living off the land." One such binary is `certutil.exe`, typically used for managing certificate services. However, attackers can leverage its built-in functionality, specifically the `urlcache` and `verifyctl` commands with the `url` option, to download arbitrary files from remote locations. This technique is observed in various campaigns, including those by `Agent Tesla` and `Mint Sandstorm`, allowing adversaries to download additional malware, tools, or configuration files directly to compromised systems. By using trusted system utilities and common file-sharing platforms like GitHub, Pastebin, and cloud storage services, attackers can blend malicious traffic with legitimate network activity, making detection more challenging for defenders. This specific detection focuses on `certutil.exe` processes initiating downloads from a broad list of known file-sharing and code-hosting domains.

## Impact

The successful exploitation of this technique allows attackers to bypass traditional perimeter defenses and introduce arbitrary payloads onto a compromised system. This can lead to a wide range of detrimental impacts, including the installation of ransomware, data exfiltration tools, keyloggers, or backdoors, ultimately enabling persistent access and further network penetration. The use of LOLBINs like `certutil.exe` for ingress tool transfer enhances an adversary's ability to remain undetected, increasing the likelihood of successful secondary infections and significant organizational damage, such as financial losses due to ransomware, reputational damage from data breaches, or operational disruption.

## Recommendation

*   Deploy the `Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE` Sigma rule to your SIEM and tune for your environment to detect `certutil.exe` abuse.
*   Enable comprehensive `process_creation` logging on all Windows endpoints (e.g., via Sysmon) to ensure visibility into `certutil.exe` executions and their command-line arguments.
*   Consider implementing network egress filtering or web proxy policies to block or monitor connections to known suspicious file-sharing domains listed in the `iocs` section, particularly for non-standard user agents or processes.
*   Implement application control policies (e.g., AppLocker, Windows Defender Application Control) to restrict the execution of `certutil.exe` or other LOLBINs to approved directories or contexts, limiting its abuse potential.
