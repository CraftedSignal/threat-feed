---
title: Suspicious File Download from File Sharing Websites - Alternate Data Stream Detection
slug: 2026-07-suspicious-file-download-ads
description: This brief details a high-severity detection aimed at identifying suspicious downloads of executable or script-like files from commonly abused file-sharing and pastebin domains, evidenced by the creation of a 'Zone.Identifier' Alternate Data Stream on Windows systems, a common initial access or payload delivery technique.
date: "2026-07-03T15:04:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - file-download
  - malware
  - initial-access
  - defense-evasion
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: Detects the download of suspicious file type from a well-known file and paste sharing domain, which creates a 'Zone.Identifier' Alternate Data Stream.
    confidence_band: high
references:
  - https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90015
  - https://www.cisa.gov/uscert/ncas/alerts/aa22-321a
  - https://fabian-voith.de/2020/06/25/sysmon-v11-1-reads-alternate-data-streams/
  - https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/
rules:
  - title: Suspicious File Download From File Sharing Websites - File Stream
    description: Detects the download of suspicious executable or script file types from well-known file and paste sharing domains, identified by the creation of a 'Zone.Identifier' Alternate Data Stream.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1564.004
    data_sources:
      - create_stream_hash
      - windows
rules_count: 1
---

This brief details a detection focused on identifying highly suspicious file downloads from commonly abused file-sharing and pastebin websites. Attackers frequently leverage legitimate services like GitHub, Mega.nz, or various paste sites to host malicious payloads, making it difficult for traditional network filtering to distinguish between benign and malicious traffic. The detection specifically targets downloads of executable or script-like files (e.g., .exe, .dll, .hta, .vbs) that trigger the creation of a 'Zone.Identifier' Alternate Data Stream (ADS) on Windows systems. This ADS indicates the file originated from an untrusted internet zone, serving as a critical indicator when combined with suspicious file types and source domains. This behavior is a common initial access or payload delivery method, bypassing some security controls by using trusted services.

## Impact

Successful exploitation following such a download typically leads to initial compromise of the endpoint. The downloaded file, if executed, could be any form of malware, including ransomware, information stealers, or remote access Trojans (RATs), granting attackers unauthorized access to the victim's system and potentially the broader network. This method is often used for targeted attacks against individuals or organizations, as attackers can tailor the payload and social engineering lures. The impact includes data exfiltration, system damage, lateral movement, and financial loss, contingent on the specific payload delivered by the attacker.

## Recommendation

*   Deploy the Sigma rule in this brief to your SIEM and tune for your environment.
*   Ensure Sysmon logging, specifically for `FileStreamHash` events (Event ID 21), is enabled on all Windows endpoints to capture the necessary telemetry for the rule.
*   Consider implementing network-level blocking or content filtering for the domains listed in the `selection_domain` of the provided Sigma rule, especially for environments where access to these sites is not business-critical, to prevent initial download attempts.
