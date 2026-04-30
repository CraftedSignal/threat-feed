---
title: Malicious Chrome Extensions Stealing Data and Opening Backdoors
slug: 2026-04-chrome-extension-backdoor
description: A coordinated campaign uses 108 malicious Chrome extensions to steal user data, inject ads, and establish backdoors on over 20,000 systems via a shared command-and-control infrastructure.
date: "2026-04-16T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - chrome-extension
  - credential-theft
  - backdoor
  - ad-injection
  - exfiltration
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1608
    technique_name: Stage Capabilities
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1115
    technique_name: Clipboard Data
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.securityweek.com/100-chrome-extensions-steal-user-data-open-backdoor/
rules:
  - title: Detect Suspicious Chrome Extension Network Activity
    description: Detects network connections initiated by Chrome extensions to domains outside of known legitimate services.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Chrome Extension Script Execution
    description: Detects the execution of suspicious scripts within the context of a Chrome extension.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A coordinated campaign involving 108 malicious Chrome extensions has been discovered. These extensions, distributed through five accounts (GameGen, InterAlt, SideGames, Rodeo Games, and Yana Project), are designed to steal user data, inject ads, and create backdoors. Over 20,000 users have installed these extensions. The extensions provide expected functionality to avoid suspicion, but malicious code runs in the background, communicating with a shared C&C infrastructure to perform nefarious activities. The extensions target various user types by masquerading as Telegram sidebar clients, slot machine and Keno games, YouTube and TikTok enhancers, a text translation tool, and page utility extensions. This campaign poses a significant threat to user privacy and system security.

## Attack Chain

1.  Users install malicious Chrome extensions from the Chrome Web Store, believing they are legitimate tools (e.g., Telegram clients, games, enhancers).
2.  Upon installation, the extensions execute JavaScript code in the background.
3.  Extensions designed for credential theft acquire Google OAuth2 Bearer tokens and exfiltrate user information (email, name, profile picture) to a remote server.
4.  Extensions targeting Telegram steal the active Telegram Web session by overwriting local storage with attacker-supplied data and force-reloading Telegram.
5.  Some extensions contain a backdoor that opens an arbitrary URL received from the C&C server in a new tab upon browser start.
6.  Other malicious activities include injecting ads into YouTube and TikTok pages, injecting content scripts into all visited pages, or proxying translation requests through attacker-controlled servers.
7.  The attacker gains access to user accounts (Google, Telegram) and can inject malicious content, redirect traffic, and steal sensitive information.

## Impact

Over 20,000 users have been affected by these malicious extensions. The campaign targets a broad range of users by using different categories of extensions. Successful exploitation can lead to stolen credentials, account takeover, data exfiltration, ad fraud, and the ability to inject arbitrary content into visited websites. The compromised systems could be used for further malicious activities.

## Recommendation

*   Monitor network connections originating from Chrome extensions for connections to unusual or suspicious domains using a network connection rule (see example rule below).
*   Implement strict policies for Chrome extension installations, including whitelisting approved extensions and blocking installation from untrusted sources.
*   Deploy the Sigma rule to detect the execution of scripts from the malicious extensions to your SIEM and tune for your environment.
