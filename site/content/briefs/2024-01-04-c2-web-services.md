---
title: Detection of Command and Control Activity via Commonly Abused Web Services
slug: 2024-01-04-c2-web-services
description: This rule detects command and control activity using common web services by identifying Windows hosts making DNS requests to a list of commonly abused web services from processes outside of known program locations, potentially indicating adversaries attempting to blend malicious traffic with legitimate network activity.
date: "2024-01-04T12:00:00Z"
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

Adversaries may implement command and control (C2) communications that use common web services to hide their activity. This attack technique is typically targeted at an organization and uses web services common to the victim network, which allows the adversary to blend into legitimate traffic activity. These popular services are typically targeted since they have most likely been used before compromise, which helps malicious traffic blend in. This detection focuses on identifying connections…
