---
title: Webworm APT Updates TTPs with Discord and Microsoft Graph C2
slug: 2026-05-webworm-new-techniques
description: The Webworm APT group is using updated tactics, techniques, and procedures, including new backdoors using Discord and Microsoft Graph API for command and control, custom proxy tools, and GitHub for malware staging, shifting focus to European governmental organizations.
date: "2026-05-21T06:46:03Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Webworm
cpes:
  - cpe:2.3:a:squirrelmail:squirrelmail:1.4.22:*:*:*:*:*:*:*
tags:
  - webworm
  - apt
  - discord
  - microsoft graph api
  - proxy tool
vendors:
  - Microsoft
  - GitHub
  - Vultr
  - IT7 Networks
  - Amazon
products:
  - Microsoft Graph API
  - OneDrive
  - SoftEther VPN
  - mRemoteNG
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595.002
    technique_name: 'Active Scanning: Vulnerability Scanning'
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595.003
    technique_name: 'Active Scanning: Wordlist Scanning'
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588.006
    technique_name: 'Obtain Capabilities: Vulnerabilities'
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1583.004
    technique_name: 'Acquire Infrastructure: Server'
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1583.003
    technique_name: 'Acquire Infrastructure: Virtual Private Server'
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1584.006
    technique_name: 'Compromise Infrastructure: Web Services'
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1608.002
    technique_name: 'Stage Capabilities: Upload Tool'
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053.005
    technique_name: 'Scheduled Task/Job: Scheduled Task'
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
cves:
  - id: CVE-2017-7692
    cvss: 8.8
    epss: 0.15603
references:
  - https://www.welivesecurity.com/en/eset-research/webworm-new-burrowing-techniques/
  - CVE-2017-7692
iocs:
  - type: domain
    value: wamanharipethe.s3.ap-south-1.amazonaws[.]com
ioc_counts:
  domain: 1
rules:
  - title: Detect Webworm Tool Download From GitHub
    description: Detects download of Webworm tools from their GitHub repository
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1608.002
    data_sources:
      - network_connection
      - windows
  - title: Detect Proxy Tool Execution
    description: Detects the execution of known proxy tools used by Webworm.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

ESET researchers have detailed the 2025 activities of Webworm, a China-aligned APT group known since 2022. The group, originally targeting Asian organizations, has shifted its focus to European governmental organizations and a South African university. Webworm has moved away from traditional backdoors such as McRat and Trochilus and now utilizes legitimate or semi-legitimate tools, as well as custom proxy solutions. Key additions to their toolset include EchoCreep, a Discord-based backdoor, and GraphWorm, which leverages Microsoft Graph API for command and control. Webworm also employs GitHub repositories to stage malware for direct download onto compromised systems, enhancing stealth and evading detection.

## Attack Chain

1.  Initial compromise of a system through an undisclosed method, possibly exploiting CVE-2017-7692.
2.  Establishment of persistence using GraphWorm via registry modifications.
3.  Deployment of EchoCreep, utilizing Discord channels for C&C communication via crafted HTTP requests.
4.  Utilization of GraphWorm with Microsoft Graph API using OneDrive endpoints to retrieve jobs and upload victim information.
5.  Configuration retrieval for WormFrp from a compromised Amazon S3 bucket at `wamanharipethe.s3.ap-south-1.amazonaws[.]com`.
6.  Credential dumping using SharpSecretsdump, uploaded to the compromised S3 bucket.
7.  Lateral movement and internal reconnaissance using tools staged on GitHub and custom proxy tools like WormFrp, ChainWorm, and SmuxProxy.
8.  Data exfiltration of sensitive information, such as VM snapshots and network diagrams, through the compromised Amazon S3 bucket.

## Impact

Webworm's activities in 2025 targeted governmental organizations in Belgium, Italy, Serbia, and Poland, as well as a university in South Africa. Compromised Amazon S3 buckets were used for data exfiltration, potentially leading to exposure of sensitive government data and infrastructure details. Decryption of over 400 Discord messages revealed reconnaissance commands used against more than 50 unique targets, highlighting the scope of the group's operations. Successful exploitation of virtual machine management environments could lead to widespread infrastructure compromise.

## Recommendation

*   Monitor network traffic for connections to known Webworm infrastructure, including Vultr and IT7 Networks ASNs (see IOCs) and Discord traffic for abnormal C2 activity.
*   Implement detections for processes utilizing the Microsoft Graph API for unusual activities, specifically uploads to OneDrive (see GraphWorm description).
*   Monitor for scheduled tasks resembling "MicrosoftSSHUpdate" used by EchoCreep for persistence (see Attack Chain).
*   Block access to the compromised S3 bucket `wamanharipethe.s3.ap-south-1.amazonaws[.]com` at the network perimeter (see IOCs).
*   Deploy the Sigma rule "Detect Webworm Tool Download From GitHub" to detect download of known tools (see rules).
*   Monitor process creation events for the execution of `SharpSecretsdump` from unusual locations (see Attack Chain).
*   Implement the Sigma rule to detect proxy tool execution, focusing on named proxy tools (see rules).
