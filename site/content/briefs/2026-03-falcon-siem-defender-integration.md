---
title: CrowdStrike Falcon Next-Gen SIEM Integrates with Microsoft Defender EDR
slug: 2026-03-falcon-siem-defender-integration
description: CrowdStrike Falcon Next-Gen SIEM now supports third-party EDR solutions like Microsoft Defender, enabling unified detection and response across diverse environments, addressing the challenges of cross-domain attacks and fragmented security systems.
date: "2026-03-29T06:23:07Z"
severities:
  - medium
tags:
  - siem
  - edr
  - threat-intelligence
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-next-gen-siem-supports-third-party-edr-tools-starting-with-microsoft-defender/
rules:
  - title: Detect Data Ingestion from Microsoft Defender into Falcon SIEM
    description: Detects when Microsoft Defender data is being ingested into Falcon SIEM, which may indicate the integration is being used for broader analysis.
    platform: sigma
    severity: informational
    tactics:
      - detection
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Activity After Defender-SIEM Integration
    description: Detects suspicious network connections originating from processes that have been correlated with Defender telemetry.
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

CrowdStrike's Falcon Next-Gen SIEM is expanding its capabilities to support third-party EDR solutions, beginning with Microsoft Defender. Announced on March 23, 2026, this enhancement allows organizations to integrate Microsoft Defender telemetry into Falcon Next-Gen SIEM, streamlining detection, investigation, and response without requiring changes to existing endpoint deployments. This integration addresses the increasing challenge of adversaries exploiting gaps across endpoint, identity…
