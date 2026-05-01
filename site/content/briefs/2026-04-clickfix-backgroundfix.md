---
title: ClickFix 'BackgroundFix' Campaign Delivers CastleLoader, NetSupport RAT, and CastleStealer
slug: 2026-04-clickfix-backgroundfix
description: The 'BackgroundFix' ClickFix campaign uses social engineering to trick victims into downloading malware disguised as a free image-editing tool, leading to the deployment of CastleLoader, NetSupport RAT for remote access, and CastleStealer for credential theft.
date: "2026-04-30T13:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickfix
  - malware
  - social-engineering
  - rat
  - infostealer
  - castleloader
  - netsupport
vendors:
  - Microsoft
products:
  - Microsoft Windows
  - Microsoft 365
  - Google Workspace
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
references:
  - https://www.huntress.com/blog/clickfix-castleloader-backgroundfix
iocs:
  - type: domain
    value: cheeshomireciple[.]com
ioc_counts:
  domain: 1
rules:
  - title: Detect Finger.exe Executing with Suspicious Domain
    description: Detects execution of finger.exe querying a domain for command execution, indicative of initial payload delivery.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Network Connection to Known NetSupport RAT C2 Ports
    description: Detects network connections to port 688, commonly used by NetSupport RAT for command and control.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The BackgroundFix campaign is a social engineering scheme using fake "remove your photo background" services to deliver malware. Victims are lured to malicious sites mimicking legitimate image editing tools. The sites feature fake upload interfaces, progress bars, and download buttons to appear authentic. This campaign delivers a multi-stage payload, starting with CastleLoader. CastleLoader then drops NetSupport RAT, enabling remote access for the attackers, and CastleStealer, a custom .NET stealer designed to exfiltrate browser credentials, wallet extension data, and Telegram session files. This campaign appears to be active, with multiple domains sharing the same template.

## Attack Chain

1. Victim searches for an online background removal tool and lands on a malicious BackgroundFix site.
2. The victim uploads an image to the fake website.
3. After clicking a checkbox, the site instructs the victim to copy a command to their clipboard.
4. The copied command executes `finger.exe` to query `cheeshomireciple[.]com`
5. `finger.exe` retrieves a batch script from the C2 server.
6. The batch script executes commands to download and execute further payloads.
7. CastleLoader is deployed, subsequently dropping NetSupport RAT and CastleStealer.
8. NetSupport RAT grants the attacker remote access, while CastleStealer exfiltrates sensitive data.

## Impact

Successful attacks result in the installation of NetSupport RAT, granting attackers remote control over the compromised system. Additionally, CastleStealer exfiltrates sensitive information such as browser credentials, wallet extension data, and Telegram session files. This stolen data can be used for further malicious activities, including financial fraud, identity theft, and unauthorized access to sensitive accounts. The active nature of the campaign and the use of multiple domains suggest a broad targeting scope.

## Recommendation

*   Monitor process creation events for the execution of `finger.exe` with command-line arguments pointing to external domains (IOC: `cheeshomireciple[.]com`).
*   Deploy the Sigma rule to detect the execution of `finger.exe` to identify potential initial access attempts.
*   Block the C2 domain `cheeshomireciple[.]com` at the DNS resolver to prevent initial payload delivery.
*   Monitor network connections for NetSupport RAT C2 communications on port 688 to detect compromised systems (IOCs: `poronto[.]com:688`, `giovettiadv[.]com:688`).
