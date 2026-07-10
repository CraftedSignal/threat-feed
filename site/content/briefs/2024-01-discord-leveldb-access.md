---
title: Non-Discord Application Accessing Discord LevelDB Database
slug: 2024-01-discord-leveldb-access
description: This analytic detects non-Discord applications accessing the Discord LevelDB database by monitoring Windows Security Event logs (event code 4663), which may indicate attempts to steal Discord credentials or access sensitive user data, potentially compromising user profiles, messages, and other critical information.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - stealer
  - windows
vendors:
  - Discord
products:
  - Discord
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1012
    technique_name: Query Registry
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.404keylogger
rules:
  - title: Detect Non Discord App Access Discord LevelDB
    description: Detects non-Discord applications accessing the Discord LevelDB database, indicating potential credential theft.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - windows
  - title: Detect Non Discord App Access Discord LevelDB using Object Name
    description: Detects non-Discord applications accessing the Discord LevelDB database, using object name, indicating potential credential theft.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This detection focuses on identifying unauthorized access to Discord's LevelDB database by non-Discord applications on Windows systems. The LevelDB database stores sensitive user information, including credentials and message history. Attackers may attempt to access this database to steal credentials or extract other valuable data. The detection uses Windows Security Event logs, specifically event ID 4663, to monitor file access attempts to the LevelDB directory. The activity is flagged when a process other than Discord (discord.exe) attempts to access the LevelDB database files. Successful exploitation could allow attackers to compromise user accounts and access sensitive information. This activity is associated with credential stealer malware families such as Snake Keylogger, StealC Stealer, PXA Stealer and BlankGrabber Stealer.

## Attack Chain

1.  The attacker deploys malware on a compromised system.
2.  The malware attempts to access the Discord LevelDB database.
3.  The malware process triggers Windows Security Event ID 4663.
4.  The event log records the process name, path, and the accessed file path.
5.  The detection logic identifies that a non-Discord process is accessing the LevelDB database.
6.  The malware extracts credentials and sensitive data from the LevelDB database.
7.  The malware exfiltrates the stolen data to a remote server.

## Impact

Compromised Discord user accounts may lead to unauthorized access to private messages, servers, and personal information. Attackers can use stolen credentials to impersonate users, spread malware, or conduct further malicious activities. The impact includes potential data breaches, financial loss, and reputational damage to affected users and organizations. Credential stealer malware families are known to target various sectors, and successful attacks can lead to widespread data compromise.

## Recommendation

*   Enable "Audit Object Access" in Group Policy for event code 4663 to ensure proper logging of file access events as described in the "how_to_implement" section.
*   Deploy the Sigma rule "Detect Non Discord App Access Discord LevelDB" to your SIEM and tune for your environment.
*   Investigate any detected events to determine the scope and impact of the unauthorized access.
*   Block the identified malicious process names and paths to prevent further access to the LevelDB database.
