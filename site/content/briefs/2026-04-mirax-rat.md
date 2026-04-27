---
title: Mirax RAT Targeting Android Users in Europe
slug: 2026-04-mirax-rat
description: Mirax RAT, a new Android RAT distributed as MaaS, is targeting European users by turning infected devices into residential proxy nodes and enabling credential theft via overlay and notification injection.
date: "2026-04-16T12:00:00Z"
severities:
  - high
tags:
  - android
  - rat
  - mirax
  - malware-as-a-service
  - proxy
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1621
    technique_name: Multi-Factor Authentication Request Generation
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1113
    technique_name: Screen Capture
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.securityweek.com/mirax-rat-targeting-android-users-in-europe/
rules:
  - title: Android App Installation from Unknown Sources
    description: Detects the installation of applications from unknown sources on Android devices, which is a common step in Mirax RAT infections.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - linux
  - title: Suspicious Network Connection from Newly Installed Android App
    description: Detects network connections originating from newly installed Android applications, potentially indicating command and control activity.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The Mirax RAT is a newly identified Android Remote Access Trojan (RAT) that has been actively targeting users in Europe since March 2026. It's offered as Malware-as-a-Service (MaaS) to a small group of affiliates, primarily Russian-speaking actors, through tiered subscription models. Since December 2025, Mirax has been promoted on underground forums and used in multiple campaigns. The RAT's distribution relies on malicious advertisements on Meta platforms like Facebook, Instagram, and…
