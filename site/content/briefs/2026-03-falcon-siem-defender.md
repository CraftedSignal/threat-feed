---
title: CrowdStrike Falcon Next-Gen SIEM Integrates with Microsoft Defender
slug: 2026-03-falcon-siem-defender
description: CrowdStrike's Falcon Next-Gen SIEM is expanding to support third-party EDR solutions, starting with Microsoft Defender, to unify detection, investigation, and response without requiring a Falcon sensor.
date: "2026-03-30T06:30:00Z"
severities:
  - medium
tags:
  - siem
  - edr
  - microsoft defender
  - crowdstrike falcon
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-next-gen-siem-supports-third-party-edr-tools-starting-with-microsoft-defender/
rules:
  - title: Data Stream Contains Falcon Onum
    description: Detects when a data stream contains Falcon Onum indicating data transformation
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - network_connection
      - windows
  - title: ExtraHop Network Connection
    description: Detects network connections to ExtraHop indicating possible data integration
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CrowdStrike is enhancing its Falcon Next-Gen SIEM platform to incorporate telemetry from third-party endpoint detection and response (EDR) solutions, beginning with Microsoft Defender. Announced on March 23, 2026, this integration allows organizations to modernize their security operations center (SOC) by unifying detection, investigation, and response workflows without mandating the replacement of existing endpoint agents. This aims to address the increasing complexity of modern attacks that…
