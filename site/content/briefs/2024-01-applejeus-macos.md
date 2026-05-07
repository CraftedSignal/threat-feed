---
title: Lazarus Group's AppleJeus macOS Backdoor via JMT Trader
slug: 2024-01-applejeus-macos
description: The Lazarus APT group is distributing a macOS backdoor named AppleJeus via a fake cryptocurrency trading application called JMT Trader, persisting through a launch daemon and communicating with the C&C server beastgoc.com.
date: "2024-01-03T15:30:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Lazarus Group
  - HIDDEN COBRA
  - LABYRINTH CHOLLIMA
  - Diamond Sleet
  - Zinc
tags:
  - applejeus
  - macos
  - lazarus group
  - backdoor
  - cryptocurrency
vendors:
  - Apple
products:
  - macOS
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://objective-see.org/blog/blog_0x49.html
iocs:
  - type: domain
    value: beastgoc.com
  - type: url
    value: https://beastgoc.com/grepmonux.php
  - type: ip
    value: 185.228.83.32
ioc_counts:
  domain: 1
  ip: 1
  url: 1
rules:
  - title: Detect AppleJeus CrashReporter Execution
    description: Detects execution of the AppleJeus CrashReporter binary with the 'Maintain' argument.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - persistence
    techniques:
      - T1543.001
    data_sources:
      - process_creation
      - macos
  - title: Detect AppleJeus C2 Communication
    description: Detects network connections to the AppleJeus C&C server beastgoc.com.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - macos
rules_count: 2
---

The Lazarus APT group is distributing a new variant of its AppleJeus macOS backdoor through a fake cryptocurrency trading application called "JMT Trader." The attackers created a fake company and website (jmttrading.org) to distribute the malicious application. The JMTTrader_Mac.dmg disk image contains a package installer (JMTTrader.pkg) that installs the AppleJeus backdoor. The malware utilizes a launch daemon for persistence and communicates with a command-and-control server to receive instructions. This campaign, observed in October 2019, targets macOS users interested in cryptocurrency trading and highlights Lazarus Group's continued focus on financial gain. The analyzed sample's SHA1 hash is 74390fba9445188f2489959cb289e73c6fbe58e4.

## Attack Chain

1.  A user is lured to the fake JMT Trading website (jmttrading.org) and downloads the JMTTrader_Mac.dmg disk image.
2.  The user mounts the disk image, which contains the JMTTrader.pkg installer.
3.  The user executes the JMTTrader.pkg installer, which prompts for administrative privileges.
4.  The postinstall script within the package moves `.org.jmttrading.plist` to `/Library/LaunchDaemons/org.jmttrading.plist` and sets permissions.
5.  The script creates the `/Library/JMTTrader` directory and moves `.CrashReporter` to `/Library/JMTTrader/CrashReporter`, setting execute permissions.
6.  The script executes `/Library/JMTTrader/CrashReporter` with the `Maintain` command-line argument for initial connection.
7.  The `CrashReporter` binary connects to the C&C server at `beastgoc.com` via HTTPS POST requests to `/grepmonux.php`, sending system information (token, version, PID) after XOR "encryption".
8.  The backdoor awaits commands from the C&C server to perform malicious activities.

## Impact

Successful infection allows the Lazarus Group to gain persistent remote access to the compromised macOS system. This can lead to the theft of cryptocurrency, sensitive financial data, or further propagation of malware within the victim's network. While specific victim counts are unavailable, previous AppleJeus campaigns have targeted cryptocurrency exchanges, potentially resulting in substantial financial losses.

## Recommendation

*   Monitor process creations for `/Library/JMTTrader/CrashReporter` executing with the `Maintain` argument, using the Sigma rule "Detect AppleJeus CrashReporter Execution".
*   Monitor network connections to `beastgoc.com` on TCP port 443, using the Sigma rule "Detect AppleJeus C2 Communication".
*   Block the C&C domain `beastgoc.com` at the DNS resolver to prevent initial communication.
*   Inspect macOS systems for the presence of the launch daemon `/Library/LaunchDaemons/org.jmttrading.plist` and the `CrashReporter` binary in `/Library/JMTTrader/`.
