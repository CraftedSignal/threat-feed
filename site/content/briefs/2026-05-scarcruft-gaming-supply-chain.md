---
title: ScarCruft Compromises Gaming Platform in Supply-Chain Attack
slug: 2026-05-scarcruft-gaming-supply-chain
description: The ScarCruft APT group conducted a supply-chain attack targeting the Yanbian region by compromising a gaming platform, sqgame, used by ethnic Koreans, trojanizing Windows and Android games with the BirdCall backdoor for espionage activities since late 2024.
date: "2026-05-06T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - ScarCruft
tags:
  - supply-chain attack
  - apk
  - backdoor
  - android
  - windows
  - scarcruft
vendors:
  - sqgame
products:
  - Yanbian Red Ten
  - New Drawing
  - sqgame
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1584.004
    technique_name: Compromise Infrastructure
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1587.001
    technique_name: Develop Capabilities
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1608.001
    technique_name: Stage Capabilities
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: Supply Chain Compromise
references:
  - https://www.welivesecurity.com/en/eset-research/rigged-game-scarcruft-compromises-gaming-platform-supply-chain-attack/
iocs:
  - type: url
    value: https://www.sqgame[.]net
  - type: url
    value: http://sqgame.com[.]cn/ybht.apk
  - type: url
    value: http://sqgame.com[.]cn/sqybhs.apk
  - type: url
    value: http://xiazai.sqgame.com[.]cn/dating/20240429.zip
ioc_counts:
  url: 4
rules:
  - title: Detect Trojanized mono.dll
    description: Detects the presence of the trojanized mono.dll library, indicating a compromised sqgame Windows client update.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1195.002
    data_sources:
      - file_event
      - windows
  - title: Detect Network Connection to Compromised sqgame Domain
    description: Detects network connections to the sqgame domain known to host trojanized games.
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

ESET researchers uncovered a multiplatform supply-chain attack by the North Korea-aligned APT group ScarCruft, targeting the Yanbian region in China since late 2024. The group compromised the Windows and Android components of a video game platform called sqgame, which is dedicated to Yanbian-themed games. ScarCruft trojanized the games with a backdoor named BirdCall, originally known to target Windows, with the Android version discovered as part of this supply-chain attack. The compromised gaming platform distributed malicious updates and trojanized Android games, aiming to collect personal data, documents, screenshots, and voice recordings from users in the targeted region.

## Attack Chain

1.  ScarCruft compromises the sqgame gaming platform's infrastructure, likely through exploiting vulnerabilities or weak credentials.
2.  The attackers trojanize the mono.dll library within an update package for the Windows desktop client of the sqgame platform, hosted at http://xiazai.sqgame.com[.]cn/dating/20240429.zip.
3.  Legitimate users of the sqgame platform download and install the compromised update package, unknowingly deploying the trojanized mono.dll on their Windows systems.
4.  The trojanized mono.dll acts as a downloader, retrieving and executing the RokRAT backdoor on the victim's machine, which then deploys the more sophisticated BirdCall backdoor.
5.  ScarCruft trojanizes Android game APKs (延边红十 and 新画图) available for download on the official sqgame website, https://www.sqgame[.]net.
6.  Victims download and install the trojanized Android games (ybht.apk and sqybhs.apk), which contain the Android version of the BirdCall backdoor, onto their Android devices.
7.  The BirdCall backdoor (both Windows and Android versions) establishes command and control (C2) communication with attacker-controlled infrastructure.
8.  The BirdCall backdoor collects sensitive information, including contacts, SMS messages, call logs, documents, media files, private keys, screenshots, and voice recordings, and exfiltrates the data to the attackers, serving as espionage.

## Impact

This supply-chain attack targeted ethnic Koreans living in the Yanbian region, a community of interest to the North Korean regime. The compromise of the gaming platform could have affected thousands of users, leading to the theft of personal data, sensitive documents, and private communications. If successful, ScarCruft gains access to information on individuals based in or originating from the Yanbian region, likely refugees or defectors deemed of interest to North Korea.

## Recommendation

*   Monitor network traffic for connections to the compromised sqgame domain (sqgame.com[.]cn) and associated IPs (39.106.249[.]68) as these are used to deliver malicious content.
*   Implement file integrity monitoring for mono.dll and alert on modifications to this file, using the SHA-1 hash (95BDB94F6767A3CCE6D92363BBF5BC84B786BDB0) as a baseline for comparison.
*   Block downloads from the malicious URLs (http://sqgame.com[.]cn/ybht.apk, http://sqgame.com[.]cn/sqybhs.apk, http://xiazai.sqgame.com[.]cn/dating/20240429.zip) at the network perimeter.
