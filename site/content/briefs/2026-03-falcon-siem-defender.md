---
title: CrowdStrike Falcon SIEM Integration with Microsoft Defender
slug: 2026-03-falcon-siem-defender
description: CrowdStrike Falcon Next-Gen SIEM is expanding to support third-party EDR solutions, starting with Microsoft Defender, enabling organizations to extend their AI-native SOC and unify detection, investigation, and response across heterogeneous environments without requiring a Falcon sensor.
date: "2026-03-30T06:19:01Z"
severities:
  - medium
tags:
  - siem
  - edr
  - threat-intelligence
  - ecosystem-integration
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-next-gen-siem-supports-third-party-edr-tools-starting-with-microsoft-defender/
rules:
  - title: Detecting Microsoft Defender Telemetry in Falcon SIEM
    description: Detects events indicative of Microsoft Defender telemetry being ingested and processed within CrowdStrike Falcon SIEM.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - process_creation
      - windows
  - title: Federated Search Activity in Falcon SIEM
    description: Detects the use of federated search capabilities in Falcon SIEM to query external data sources like Falcon LogScale or Amazon S3.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1592.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike is enhancing its Falcon Next-Gen SIEM platform to integrate with third-party endpoint detection and response (EDR) solutions, beginning with Microsoft Defender. This integration aims to provide organizations with a unified security operations center (SOC) experience, allowing them to leverage existing EDR deployments without needing to replace them with the Falcon sensor. The move addresses the growing challenges of modern cybersecurity, where attacks often span multiple…
