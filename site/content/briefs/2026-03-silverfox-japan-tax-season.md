---
title: Silver Fox Spearphishing Campaign Targeting Japanese Firms During Tax Season
slug: 2026-03-silverfox-japan-tax-season
description: The Silver Fox threat actor is conducting a targeted spearphishing campaign against Japanese manufacturers and other businesses, exploiting the annual tax filing and organizational change season by sending emails containing malicious attachments that deploy ValleyRAT, leading to remote access, data theft, and persistence.
date: "2026-03-28T12:00:00Z"
severities:
  - high
actors:
  - Silver Fox
tags:
  - silverfox
  - spearphishing
  - valleyrat
  - japan
  - taxseason
  - remoteaccesstrojan
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.welivesecurity.com/en/business-security/cunning-predator-how-silver-fox-preys-japanese-firms-tax-season/
rules:
  - title: Detect ValleyRAT Execution
    description: Detects the execution of ValleyRAT, a remote access trojan used by Silver Fox.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Archive Download from File Sharing Services
    description: Detects suspicious downloads of archive files (ZIP, RAR) from file sharing services often used for malicious payload delivery.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The Silver Fox threat actor, active since at least 2023, is conducting a spearphishing campaign targeting Japanese organizations during their annual tax filing and organizational change season. Initially focused on Chinese-speaking targets, Silver Fox has expanded its operations into Southeast Asia, Japan, and potentially North America. This campaign specifically exploits the high volume of legitimate financial and HR-related communications that occur during this period, making it more likely…
