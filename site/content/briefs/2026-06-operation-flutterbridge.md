---
title: 'Operation FlutterBridge: macOS Malvertising Campaign Spreads New FlutterShell Backdoor'
slug: 2026-06-operation-flutterbridge
description: Operation FlutterBridge is a malvertising campaign targeting macOS users with the new FlutterShell backdoor, which uses malicious desktop applications for adware distribution and provides backdoor capabilities such as command execution and file system manipulation, with some variants using AI summarization for data exfiltration.
date: "2026-06-02T10:11:08Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - CL-CRI-1089
tags:
  - malvertising
  - macos
  - backdoor
vendors:
  - Google
  - Apple
  - Palo Alto Networks
products:
  - Chrome
  - Advanced WildFire
  - Advanced URL Filtering and Advanced DNS Security
  - Cortex Agentix Threat Intel Agent
  - Cortex XDR
  - Cortex XSIAM
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/
  - https://www.dart.dev
  - https://flutter.dev
iocs:
  - type: domain
    value: atsheisdomestic[.]org
  - type: domain
    value: etoftheappyrince[.]org
  - type: domain
    value: healightejustb[.]org
  - type: domain
    value: sinterfumesco[.]com
  - type: domain
    value: ads-parkpro[.]com
  - type: domain
    value: adsparkpro[.]top
  - type: domain
    value: adsparkpro[.]net
  - type: domain
    value: softwe[.]art
ioc_counts:
  domain: 8
rules:
  - title: Detect FlutterShell - PodcastsLounge Bundle ID
    description: Detects execution of PodcastsLounge application based on bundle ID
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - macos
  - title: Detect FlutterShell - PDF-Brain Bundle ID
    description: Detects execution of PDF-Brain application based on bundle ID
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - macos
  - title: Detect FlutterShell - PDF-Ninja Bundle ID
    description: Detects execution of PDF-Ninja application based on bundle ID
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - macos
rules_count: 3
---

Operation FlutterBridge is a malvertising campaign targeting macOS users, observed since late 2025 as an expansion of the JSCoreRunner campaign. The financially motivated attackers behind CL-CRI-1089 transitioned from delivering adware to adware with backdoor capabilities. This campaign distributes FlutterShell, a macOS backdoor built using the Flutter framework. FlutterShell infects targets with adware via malicious desktop applications and possesses backdoor capabilities, including shell command execution, file system manipulation, and environment variable exfiltration. Some variants use AI summarization features for data exfiltration. The campaign targets a global audience, emphasizing Anglophone and Western European markets, through Google Ads, using shell companies to bypass ad-network vetting.

## Attack Chain

1.  The attacker deploys malicious advertisements using a network of Google-verified shell companies.
2.  The user is tricked into downloading a DMG installer masquerading as a legitimate application (podcast player or PDF viewer).
3.  The DMG is opened, and the application bundle is installed.
4.  The application, signed with a valid Apple Developer ID and notarized, executes.
5.  FlutterShell waits for a duration received from the C2 server before contacting the attackers' website.
6.  The application loads malicious JavaScript code from the attacker's website using a WebView-based architecture.
7.  The JavaScript-to-native bridge is used to execute commands and manipulate the file system.
8.  The malware modifies Google Chrome configuration files to hijack the browser, forcing traffic through an ad-filled intermediary site, and in some variants exfiltrates documents through an attacker-controlled server.

## Impact

Operation FlutterBridge targets a global audience, emphasizing Anglophone and Western European markets. Successful attacks lead to adware infection, unauthorized command execution, file system manipulation, and potential data exfiltration via AI summarization features. The attackers use shell companies to bypass ad network vetting, indicating a well-resourced and persistent threat. The use of valid Apple Developer IDs and notarization helps the malware evade initial detection.

## Recommendation

*   Monitor process creation for applications signed by the identified Developer IDs (UBZDAAV97Y, FW9NHQ8922, B73CHZ24Y8) associated with FlutterShell to detect potentially malicious applications executing on macOS, as indicated in the IOC section.
*   Implement network monitoring to detect connections to the C2 domains listed in the IOC section, blocking those connections to prevent further communication from infected hosts.
*   Deploy the Sigma rule detecting the creation of files by processes with the identified Bundle IDs to identify possible post-exploitation activity.
*   Monitor DNS requests for the listed domains and URLs within your network as a high fidelity indicator of compromise and C2 activity (IOC section).
