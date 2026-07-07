---
title: Non-Discord Application Accessing Discord LevelDB
slug: 2026-07-non-discord-app-access-leveldb
description: This brief details the detection of non-Discord applications accessing the Discord LevelDB database on Windows endpoints, a critical activity often indicative of credential theft or sensitive data exfiltration by infostealer malware, which can lead to unauthorized access to user profiles and messages.
date: "2026-07-03T13:21:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-theft
  - malware
  - windows
  - endpoint
  - infostealer
vendors:
  - Discord
products:
  - Discord Desktop Client
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This activity is significant as it may indicate attempts to steal Discord credentials or access sensitive user data.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1012
    technique_name: Data from Local System
    evidence: If confirmed malicious, this could lead to unauthorized access to user profiles, messages, and other critical information, potentially compromising the security and privacy of the affected users.
    confidence_band: high
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.404keylogger
rules:
  - title: Detect Non-Discord App Accessing Discord LevelDB
    description: Detects non-Discord applications accessing Discord's LevelDB database, which may indicate credential theft or data exfiltration by infostealer malware.
    platform: sigma
    severity: high
    tactics:
      - collection
      - credential_access
    techniques:
      - T1012
      - T1552.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

This brief addresses the detection of unauthorized access to the Discord LevelDB database by non-Discord applications on Windows endpoints. This activity is significant as it may indicate attempts to steal Discord credentials or access sensitive user data. If confirmed malicious, this could lead to unauthorized access to user profiles, messages, and other critical information, potentially compromising the security and privacy of the affected users. The detection leverages Windows Security Event logs, specifically event code 4663, to identify file access attempts to the LevelDB directory by processes other than Discord. This behavior is commonly associated with infostealer malware such as StealC, Snake Keylogger, PXA Stealer, BlankGrabber Stealer, and Phantom Stealer, which target popular applications like Discord to exfiltrate user credentials and other sensitive data stored locally. Such attacks can result in account takeover, financial fraud, and further system compromise.

## Impact

If this attack succeeds, victims face unauthorized access to their Discord accounts, leading to potential account takeover, message interception, and identity theft. Attackers can leverage compromised accounts for phishing, spreading malware, or accessing linked services. The exfiltration of sensitive user data, including personal messages and potentially financial information if stored or transmitted via Discord, can have severe privacy implications and lead to significant financial and reputational damage. While specific victim counts are not available, infostealer campaigns consistently target popular platforms like Discord, indicating a broad potential user base across various sectors is at risk from this activity.

## Recommendation

*   Enable "Audit Object Access" in Group Policy for both "Success" and "Failure" on file access to ensure Windows Security Event Code 4663 is logged, as required for the Sigma rule provided.
*   Deploy the Sigma rule "Detect Non-Discord App Accessing Discord LevelDB" to your SIEM and tune for your environment to identify suspicious access attempts.
