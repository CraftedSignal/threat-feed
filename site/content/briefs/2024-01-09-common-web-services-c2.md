---
brief_id: brief-2024-01-09-common-web-services-c2
event_id: brief-2024-01-09-common-web-services-c2
revision: 2
activity_at: "2024-01-09T18:00:00Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:8aba202ebfb835af35c3cb130b553e75ef5899407287eb563500cad7f39103ca
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Detection of Command and Control Activity via Commonly Abused Web Services
slug: 2024-01-09-common-web-services-c2
description: This rule detects command and control communications using common web services to blend in with legitimate traffic by identifying network connections from Windows hosts to domains and services abused for C2, while excluding known legitimate program locations.
date: "2024-01-09T18:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
tags:
  - command-and-control
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
  - title: Connection to Commonly Abused Web Services
    description: Detects connections to commonly abused web services from Windows hosts, excluding known legitimate processes.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - dns_query
      - windows
  - title: Connection to Commonly Abused Web Services via Network Connection
    description: Detects connections to commonly abused web services from Windows hosts, excluding known legitimate processes, using network connection logs.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This detection identifies command and control (C2) communications that utilize common web services to mask malicious activity within legitimate network traffic. Attackers leverage popular web services that are commonly used within an organization to blend their C2 traffic with normal user activity, making it harder to detect. The rule focuses on Windows hosts communicating with a list of services known for abuse, such as pastebin.com, drive.google.com, dropboxapi.com, onedrive.com, ngrok.io, discordapp.com, and api.telegram.org. The rule specifically excludes connections originating from common legitimate program locations to reduce false positives, and provides mechanisms for defenders to further tune the rule by excluding other known benign processes. This helps to uncover potential C2 channels that might otherwise be missed due to their use of trusted web services.

## Attack Chain

1.  An attacker compromises a Windows host within the target network (Initial Access).
2.  The attacker installs a C2 agent on the compromised host (Persistence, Execution).
3.  The C2 agent initiates a DNS query to resolve a C2 domain such as pastebin.com or drive.google.com (Command and Control).
4.  The compromised host establishes a network connection to the resolved IP address, typically over HTTP or HTTPS (Command and Control).
5.  The C2 agent uses the web service (e.g., Pastebin) to send or receive commands and data (Command and Control).
6.  The attacker uses these commands to perform actions on the compromised host, such as data exfiltration, lateral movement, or further exploitation (Lateral Movement, Exfiltration).
7.  Data may be encoded or obfuscated to further blend in with legitimate traffic (Defense Evasion).
8.  The attacker maintains persistent access and control over the compromised host through the established C2 channel (Persistence).

## Impact

A successful attack can lead to persistent access to compromised systems, data exfiltration, further propagation within the network, and ultimately, significant damage to the organization. While this specific detection focuses on the C2 phase, successful exploitation can lead to ransomware deployment, intellectual property theft, or disruption of critical services. The low severity reflects the need for further investigation and context to confirm malicious intent, given the potential for false positives with commonly used web services.

## Recommendation

*   Deploy the Sigma rule `Connection to Commonly Abused Web Services` to your SIEM and tune for your environment, adding any prevalent false positives to the exclusion list.
*   Enable DNS query logging on Windows endpoints to improve the accuracy of the `Connection to Commonly Abused Web Services` Sigma rule.
*   Enable network connection logging on Windows endpoints to provide data for the `Connection to Commonly Abused Web Services` Sigma rule.
*   Investigate any alerts generated by the Sigma rule `Connection to Commonly Abused Web Services` by examining the process execution chain, prevalence of the executable, and digital signature status.
*   Use the references to understand the context of how common web services are used for command and control, and inform threat hunting activities.
