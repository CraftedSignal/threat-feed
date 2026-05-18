---
title: 'Q1 2026 Mobile Threat Landscape: SparkCat and Triada Updates'
slug: 2026-05-mobile-threats
description: The Q1 2026 mobile threat landscape saw a decrease in overall attack volume driven by reduced adware and RiskTool detections, while the number of unique users targeted remained stable, with new SparkCat variants on app stores and increased banking Trojan and Triada backdoor activity.
date: "2026-05-18T12:02:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - mobile
  - malware
  - trojan
  - cryptostealer
  - sparkcat
  - triada
  - android
  - ios
vendors:
  - Google
  - Apple
  - Kaspersky
products:
  - Google Play
  - App Store
  - Kaspersky mobile solutions
affected_os:
  - Android
  - iOS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1056
    technique_name: Input Capture
references:
  - https://securelist.com/malware-report-q1-2026-mobile-statistics/119819/
rules:
  - title: Detect Suspicious Usage of OCR Framework (iOS)
    description: Detects applications leveraging Apple's Vision framework for OCR, potentially indicative of SparkCat's iOS variant.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1056
    data_sources:
      - process_creation
      - macos
  - title: Detect Android Processes Using Custom Dalvik-like VM
    description: Detects Android processes that may be attempting to unpack or decrypt code using a custom Dalvik-like Virtual Machine.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - android
rules_count: 2
---

The mobile threat landscape in Q1 2026 showed a decrease in overall attack volume compared to the previous quarter, primarily due to a reduction in adware and RiskTool detections. Despite this decrease, the number of unique users targeted by these threats remained relatively stable, indicating that the risk to individual mobile users has not diminished. Notably, researchers discovered new versions of the SparkCat crypto stealer on both Google Play and the App Store. The quarter also saw threat actors increasing their production of new banking Trojans, particularly Mamont variants, and the pre-installed Triada.ag backdoor rose to the top spot in malware detections.

## Attack Chain

1.  **Distribution:** Attackers upload malicious applications containing the SparkCat crypto stealer to official app stores like Google Play and the App Store.
2.  **Installation:** Users download and install the infected applications onto their Android or iOS devices.
3.  **Obfuscation:** SparkCat employs code obfuscation techniques to conceal its malicious Rust library within the infected Android apps.
4.  **Decryption:** The malware decrypts the obfuscated malicious Rust library using a custom-built Dalvik-like virtual machine.
5.  **Credential Theft:** SparkCat steals cryptocurrency wallet credentials from the compromised device.
6.  **OCR Exploitation:** The iOS version of SparkCat leverages Apple's proprietary Vision framework for optical character recognition (OCR) to extract credentials or sensitive data from images.
7.  **Data Exfiltration:** The stolen credentials and data are exfiltrated to attacker-controlled servers.
8.  **Monetization:** Attackers use the stolen cryptocurrency wallet credentials to access and steal cryptocurrency from the victim's wallets.

## Impact

In Q1 2026, over 2.67 million attacks utilizing malware, adware, or unwanted mobile software were prevented. The rise of banking Trojans and crypto stealers like SparkCat can lead to significant financial losses for victims. Pre-installed backdoors such as Triada.ag affect a wide range of devices due to their presence in device firmware, impacting user privacy and device security. The top malware category was Trojan-Banker with 10.86% of total detections.

## Recommendation

*   Monitor application installations for suspicious behaviors, specifically those attempting to use OCR or other system frameworks in unexpected ways. Deploy the Sigma rule detecting OCR framework usage to identify potential SparkCat infections.
*   Implement detections for applications using custom Dalvik-like virtual machines to decrypt code. Deploy the provided process creation Sigma rule to identify potentially malicious processes.
*   Educate users to only install applications from trusted sources and to be cautious of applications requesting excessive permissions.
