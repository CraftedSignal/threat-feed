---
brief_id: brief-2024-01-02-common-web-services-c2
event_id: brief-2024-01-02-common-web-services-c2
revision: 2
activity_at: "2024-01-02T12:00:00Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:f6b777847607d49a8054438fff702625abb5f3a704d85edaffe0906c74c1544b
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Detection of Command and Control Activity via Common Web Services
slug: 2024-01-02-common-web-services-c2
description: This rule detects command and control communications using common web services to blend malicious traffic with legitimate network activity, identifying processes outside known program locations communicating with services like pastebin, google docs, dropbox, onedrive, ngrok, discord, and telegram which are often abused for exfiltration or command and control.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
tags:
  - command and control
  - webservice
  - windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.elastic.co/security-labs/operation-bleeding-bear
  - https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry
  - https://specterops.io/blog/2026/01/30/weaponizing-whitelists-an-azure-blob-storage-mythic-c2-profile/
rules:
  - title: Detect Suspicious Connection to Commonly Abused Web Services
    description: Detects processes making network connections to commonly abused web services, excluding known legitimate processes.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Web Service Abuse via PowerShell
    description: Detects PowerShell scripts making connections to commonly abused web services.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Discord Usage By Non-Standard Executables
    description: Detects executables outside of the standard Discord installation directory making connections to Discord domains.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

Adversaries frequently use command and control (C2) communications that leverage common web services to obfuscate their malicious activities within regular network traffic. This technique targets organizations by using web services commonly accessed within the victim's network, allowing malicious communications to blend in with legitimate traffic. Attackers prioritize popular services already in use before the compromise, further camouflaging the malicious traffic. This detection identifies processes communicating with web services known for abuse, such as file-sharing platforms, paste sites, and collaboration tools, while excluding known benign executables. The query specifically excludes common system processes and legitimate applications communicating with these services. The timeframe for analysis is set to nine months, allowing for detection of long-term C2 activities.

## Attack Chain

1.  Initial Access: An attacker gains initial access to a Windows host through an undisclosed method.
2.  Malware Deployment: The attacker deploys malware that establishes a C2 channel using a common web service.
3.  DNS Resolution: The malware resolves the DNS name of a commonly abused web service (e.g., pastebin.com) to establish communication.
4.  Network Connection: The malware establishes an outbound network connection to the resolved IP address associated with the web service.
5.  Data Exfiltration/Command Receiving: The malware sends exfiltrated data or receives commands from the attacker via the established connection to the web service.
6.  Evasion: The malware attempts to evade detection by masquerading its traffic as legitimate communication with the web service.
7.  Persistence: The malware establishes persistence to maintain C2 access across reboots, potentially through registry modifications or scheduled tasks.
8.  Lateral Movement/Impact: Depending on the attacker's objectives, the C2 channel is used to facilitate lateral movement within the network and achieve the final impact, such as data theft or system compromise.

## Impact

Successful exploitation enables attackers to establish a persistent C2 channel, exfiltrate sensitive data, and execute arbitrary commands on compromised systems. The use of common web services makes it difficult to distinguish malicious traffic from legitimate activity, potentially leading to prolonged undetected access. The impact includes potential data breaches, financial loss, reputational damage, and disruption of business operations. While the specific number of victims is unknown, organizations across various sectors are at risk.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune it to filter out legitimate connections specific to your environment, focusing on uncommon processes connecting to the listed web services (see rule: "Detect Suspicious Connection to Commonly Abused Web Services").
*   Investigate alerts generated by the Sigma rule by examining the process execution chain and verifying the digital signatures of the executables involved (see rule: "Detect Web Service Abuse via PowerShell").
*   Enable and monitor DNS query logs to identify hosts resolving domains associated with commonly abused web services (see logsource: `dns_query`).
*   Implement network segmentation to restrict outbound connections from internal hosts to only necessary web services, reducing the attack surface for C2 communication.
*   Use threat intelligence feeds to identify and block known malicious domains and IP addresses associated with C2 infrastructure.
*   Enforce strict application whitelisting policies to prevent the execution of unauthorized executables that may be used for C2 communication.
