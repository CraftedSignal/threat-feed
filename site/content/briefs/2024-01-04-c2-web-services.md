---
title: Detection of Command and Control Activity via Commonly Abused Web Services
slug: 2024-01-04-c2-web-services
description: This rule detects command and control activity using common web services by identifying Windows hosts making DNS requests to a list of commonly abused web services from processes outside of known program locations, potentially indicating adversaries attempting to blend malicious traffic with legitimate network activity.
date: "2024-01-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - windows
  - threat-detection
vendors:
  - Microsoft
  - Google
  - Brave Software
  - Opera
  - Discord
  - Slack
products:
  - OneDrive
  - Chrome
  - Brave
  - Opera
  - Discord
  - Slack
  - Microsoft 365
  - SharePoint
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1573
    technique_name: Encrypted Channel
references:
  - https://www.elastic.co/security-labs/operation-bleeding-bear
  - https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry
  - https://specterops.io/blog/2026/01/30/weaponizing-whitelists-an-azure-blob-storage-mythic-c2-profile/
rules:
  - title: Detect Commonly Abused Web Services via DNS
    description: Detects DNS queries to commonly abused web services from processes running outside of standard program directories, indicating potential command and control activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071
    data_sources:
      - dns_query
      - windows
  - title: Connection to Commonly Abused Web Services via Network Connection
    description: Detects network connections to commonly abused web services from processes running outside of standard program directories, indicating potential command and control activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Adversaries may implement command and control (C2) communications that use common web services to hide their activity. This attack technique is typically targeted at an organization and uses web services common to the victim network, which allows the adversary to blend into legitimate traffic activity. These popular services are typically targeted since they have most likely been used before compromise, which helps malicious traffic blend in. This detection focuses on identifying connections from Windows hosts to a predefined list of commonly abused web services from processes running outside of typical program installation directories, indicating a potential C2 channel leveraging legitimate services. The rule aims to detect this behavior by monitoring network connections and DNS requests originating from unusual locations.

## Attack Chain

1.  Initial access is achieved via an unknown method (e.g., phishing, exploit).
2.  Malware is installed on the victim's system, likely outside typical program directories.
3.  The malware establishes a DNS connection to a commonly abused web service (e.g., pastebin.com, raw.githubusercontent.com) to obscure C2 traffic.
4.  The malware sends encrypted or encoded commands to the web service.
5.  The web service acts as an intermediary, relaying the commands to the attacker's C2 server.
6.  The C2 server responds with instructions, which are then relayed back to the compromised host through the same web service.
7.  The malware executes the received commands, potentially leading to data exfiltration, lateral movement, or other malicious activities.
8.  The attacker maintains persistent access and control over the compromised system using the web service as a hidden C2 channel.

## Impact

Successful exploitation can lead to data theft, system compromise, and further propagation within the network. Since commonly used web services are utilized, the malicious activity can blend in with legitimate network traffic, making it difficult to detect. The impact can range from minor data breaches to complete network compromise, depending on the attacker's objectives and the level of access gained.

## Recommendation

*   Deploy the Sigma rule `Detect Commonly Abused Web Services via DNS` to your SIEM to identify suspicious DNS queries to known C2 web services originating from anomalous processes.
*   Enable DNS query logging on Windows endpoints to provide the data source required for the Sigma rule.
*   Review network connection logs for processes outside standard installation directories communicating with domains listed in the `query` section of the Sigma rule to identify potential C2 activity.
*   Implement network segmentation to limit the potential impact of compromised hosts.
