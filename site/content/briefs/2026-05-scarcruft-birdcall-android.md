---
title: ScarCruft (APT37) Deploying BirdCall Android Backdoor via Compromised Game Platform
slug: 2026-05-scarcruft-birdcall-android
description: The APT37 group (ScarCruft) is distributing an Android version of the BirdCall backdoor via a supply-chain attack targeting a Chinese video game platform, sqgame[.]net, to collect sensitive information from users.
date: "2026-05-05T09:04:13Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - ScarCruft
tags:
  - android
  - malware
  - spyware
  - apt37
  - scarcruft
  - supply-chain
vendors:
  - Google
  - Microsoft
  - ESET
products:
  - Google Play
  - Windows
  - BirdCall
affected_os:
  - Android
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1005
    technique_name: Data from Information Repositories
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1115
    technique_name: Clipboard Data
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Information Repositories
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1074
    technique_name: Data Staged
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.bleepingcomputer.com/news/security/scarcruft-hackers-push-birdcall-android-malware-via-game-platform/
iocs:
  - type: domain
    value: sqgame.net
ioc_counts:
  domain: 1
rules:
  - title: Detect Network Connection to sqgame.net
    description: Detects network connections to the sqgame.net domain, which is used to distribute the BirdCall Android malware.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Network Connection to sqgame.net (Linux)
    description: Detects network connections to the sqgame.net domain, which is used to distribute the BirdCall Android malware on Linux based systems.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The North Korean hacker group APT37, also known as ScarCruft and Ricochet Chollima, is actively distributing an Android version of their BirdCall backdoor through a supply-chain attack affecting the sqgame[.]net video game platform. This platform caters specifically to Koreans in the autonomous Yanbian region in China, which acts as a crossing point for North Korean defectors and refugees. ESET researchers discovered that APT37 created the Android version of BirdCall around October 2024 and has since developed at least seven different versions. The Android variant is designed as spyware, capable of collecting a wide range of sensitive information from compromised devices. This campaign highlights APT37's continued efforts to target specific communities with sophisticated malware.

## Attack Chain

1.  The attacker compromises the sqgame[.]net video game platform, a site hosting games for Android, iOS, and Windows.
2.  The attacker trojanizes legitimate Android application packages (APKs) available on the platform, embedding the Android version of BirdCall.
3.  Victims download the trojanized APK from the compromised game platform (sqgame[.]net) onto their Android devices.
4.  Upon installation, the BirdCall malware extracts IP geolocation information from the device.
5.  The malware collects contact lists, call logs, and SMS messages from the compromised device.
6.  The malware gathers device information including OS version, kernel version, rooted status, IMEI number, MAC address, IP address, and network information.
7.  BirdCall transmits collected data, along with battery temperature, RAM, storage, cloud configuration, backdoor version, and targeted file extensions (.jpg, .doc, .docx, .xls, .xlsx, .ppt, .pptx, .txt, .hwp, .pdf, .m4a, and .p12), to its command-and-control (C2) server.
8. The malware periodically takes screenshots and records audio via the microphone from 7 pm to 10 pm local time, exfiltrating these files to the C2 server.

## Impact

This campaign allows APT37 to harvest sensitive information from targeted individuals, including personal communications, location data, and device details. The compromise of the sqgame[.]net platform exposes users in the Korean autonomous Yanbian region in China to significant privacy risks. Successful infection enables the threat actor to conduct surveillance, gather intelligence, and potentially identify and track individuals of interest. The collected data can be used for further espionage activities or to compromise other systems and networks.

## Recommendation

*   Monitor network traffic for connections to the sqgame[.]net domain, blocking it at the firewall or DNS resolver to prevent further infections (IOC: sqgame[.]net).
*   Implement application control policies on Android devices to restrict the installation of applications from untrusted sources.
*   Deploy the Sigma rule "Detect Network Connection to sqgame.net" to identify potentially infected devices communicating with the malicious domain.
*   Educate users about the risks of downloading applications from unofficial sources and encourage them to only use trusted app stores.
*   Enable enhanced security measures like Google Play Protect to detect and remove malicious apps.
