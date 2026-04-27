---
title: CrowdStrike Falcon Next-Gen SIEM Integrates with Microsoft Defender
slug: 2026-03-falcon-siem-defender
description: CrowdStrike Falcon Next-Gen SIEM now supports third-party EDR solutions, beginning with Microsoft Defender, enabling organizations to extend their AI-native SOC and unify detection across heterogeneous environments.
date: "2026-03-28T08:12:22Z"
severities:
  - medium
tags:
  - siem
  - edr
  - microsoft defender
  - crowdstrike falcon
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-next-gen-siem-supports-third-party-edr-tools-starting-with-microsoft-defender/
rules:
  - title: Detect PowerShell Using EncodedCommand and a Network Connection
    description: Detects PowerShell processes using EncodedCommand and initiating a network connection, which is often indicative of malicious activity.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.001
      - T1071.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Process Creation with Uncommon Parent Process
    description: Detects suspicious process creations where the parent process is unusual or unexpected, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike's Falcon Next-Gen SIEM is evolving to support third-party EDR solutions, starting with Microsoft Defender, without requiring the Falcon sensor. This integration aims to modernize security operations centers (SOCs) by enabling them to unify detection, investigation, and response across diverse environments without replacing existing endpoint agents. The integration focuses on addressing the challenges of fragmented security systems, growing architectural complexity, and data…
