---
title: Suspicious File Download From File Sharing Domain Via Wget.EXE
slug: 2026-07-wget-file-sharing-download
description: This brief details a high-severity threat involving the use of `wget.exe` to download suspicious files from known file-sharing domains, a technique observed in campaigns by threat actors such as FIN7 and Mint Sandstorm, enabling initial malware delivery and subsequent system compromise.
date: "2026-07-03T15:12:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - execution
  - malware-delivery
  - command-and-control
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects potentially suspicious file downloads from file sharing domains using wget.exe
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Detects potentially suspicious file downloads from file sharing domains using wget.exe, which is used to transfer tools or payloads.
    confidence_band: high
references:
  - https://labs.withsecure.com/publications/fin7-target-veeam-servers
  - https://github.com/WithSecureLabs/iocs/blob/344203de742bb7e68bd56618f66d34be95a9f9fc/FIN7VEEAM/iocs.csv
  - https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/
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
  - title: Suspicious File Download From File Sharing Domain Via Wget.EXE
    description: Detects potentially suspicious file downloads from file sharing domains using wget.exe, often indicative of malware delivery or C2 operations.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

This threat brief focuses on the abuse of `wget.exe`, a legitimate command-line utility, by malicious actors to download suspicious files from various public file-sharing and content delivery network (CDN) domains. This technique is commonly employed during the execution phase of an attack to deliver malware, additional tools, or configuration files to compromised systems, often bypassing traditional network security controls. Prominent threat actors, including FIN7 and Mint Sandstorm (also known as Phosphorus/APT35), have been observed leveraging this method in their campaigns. For instance, FIN7 utilized such downloads in their attacks targeting Veeam servers, while Mint Sandstorm employed similar tactics in campaigns against high-profile individuals in universities and research organizations in early 2024. Detection of `wget.exe` making connections to domains like `githubusercontent.com`, `anonfiles.com`, or `mega.nz` for executable or script file types is a critical indicator of potential malicious activity.

## Impact

Successful exploitation via suspicious file downloads using `wget.exe` can lead to severe consequences. Attackers can deliver a variety of payloads, including remote access trojans (RATs), ransomware, information stealers, or custom backdoors, leading to full system compromise. This can result in unauthorized data exfiltration, disruption of operations, financial theft (as seen with FIN7), or corporate espionage (as seen with Mint Sandstorm). The long-term impact includes significant financial losses, reputational damage, and extensive recovery efforts. The scope of targeting for actors employing this technique can range from specific high-value individuals and organizations to broader campaigns.

## Recommendation

*   Deploy the Sigma rule `Suspicious File Download From File Sharing Domain Via Wget.EXE` to your SIEM/detection platform and tune it for your environment.
*   Enable `process_creation` logging on all Windows endpoints to capture `wget.exe` execution details, including command-line arguments.
*   Review network traffic logs for connections to the domains listed in the `iocs` section and consider blocking or alerting on outbound connections from sensitive systems to these domains.
