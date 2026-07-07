---
title: Suspicious Process DNS Queries to Discord
slug: 2026-07-suspicious-discord-dns-query
description: This brief identifies a detection for non-legitimate processes making DNS queries to Discord domains, indicating potential malware attempting to download additional payloads, as seen in campaigns like WhisperGate, leading to further code execution and system compromise.
date: "2026-07-03T13:27:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - malware
  - c2
  - initial-access
  - execution
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This could indicate malware attempting to download additional payloads from Discord, potentially leading to further code execution and compromise of the affected system.
    confidence_band: med
references:
  - https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
  - https://medium.com/s2wblog/analysis-of-destructive-malware-whispergate-targeting-ukraine-9d5d158f19f3
iocs:
  - type: domain
    value: discord.com
  - type: domain
    value: cdn.discordapp.com
ioc_counts:
  domain: 2
rules:
  - title: Suspicious Process With Discord DNS Query
    description: Detects non-legitimate processes making DNS queries to Discord domains, often indicating malware leveraging Discord for command and control or payload hosting, as seen in the WhisperGate campaign.
    platform: sigma
    severity: high
    tactics:
      - execution
      - impact
    techniques:
      - T1059.005
    data_sources:
      - dns_query
      - windows
rules_count: 1
---

This threat brief focuses on detecting anomalous network activity where a suspicious process, not associated with the legitimate Discord application, performs DNS queries to Discord-related domains. This behavior is a key indicator of potential malicious activity, as adversaries frequently abuse legitimate services like Discord's content delivery network (CDN) to host and distribute malware payloads. A notable example is the WhisperGate campaign, which leveraged Discord for malicious file hosting. The detection relies on Sysmon Event ID 22 logs, specifically looking for DNS queries containing "discord" in the query name originating from processes outside of known legitimate Discord application paths (e.g., `AppData\Local\Discord`, `Program Files`). If confirmed malicious, this activity strongly suggests an attempt by malware to retrieve secondary stages or tools, ultimately aiming for further compromise and impact on the affected system.

## Attack Chain

1.  An attacker achieves initial execution of a malicious payload on a target system, often disguised as a legitimate application or delivered via social engineering.
2.  The malicious process, now running on the victim machine, attempts to resolve a domain hosted on Discord's infrastructure via a DNS query (Sysmon Event ID 22).
3.  The DNS query successfully resolves, providing the attacker's malware with the IP address of a Discord-hosted resource (e.g., a file on Discord's CDN).
4.  The malicious process initiates a connection to the resolved Discord IP address and downloads additional malicious components or secondary stage payloads.
5.  The newly downloaded payloads are executed, leading to further malicious activities such as establishing persistence, escalating privileges, or deploying additional tools.
6.  The attacker achieves their final objective, which may include data exfiltration, system damage (as in data destruction campaigns like WhisperGate), or deploying ransomware, resulting in system compromise.

## Impact

The successful execution of malware leveraging Discord for C2 or payload delivery can lead to significant consequences, ranging from data exfiltration and credential theft to complete system compromise or data destruction. Campaigns like WhisperGate, which exploited such methods, demonstrated the potential for widespread data wiping across targeted organizations. While this detection doesn't specify victim counts, the technique is widely applicable, making it a threat to any organization where endpoints are not adequately monitored for anomalous network connections or where Discord usage is not strictly controlled or egress filtered.

## Recommendation

*   Enable Sysmon process-creation and DNS query logging (Event ID 22) on all Windows endpoints to facilitate the detection of suspicious processes making Discord DNS queries.
*   Deploy the Sigma rule "Suspicious Process With Discord DNS Query" to your SIEM and tune it for your environment, specifically by identifying and allowlisting any legitimate, non-Discord applications that may legitimately query Discord domains (e.g., specific gaming clients or bots).
*   Monitor for network connections and DNS queries to `*discord*` domains originating from processes other than the official Discord client, investigating any anomalous activity immediately.
