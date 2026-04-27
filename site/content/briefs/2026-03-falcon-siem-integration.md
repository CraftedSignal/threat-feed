---
title: CrowdStrike Falcon Next-Gen SIEM Integrates with Microsoft Defender
slug: 2026-03-falcon-siem-integration
description: CrowdStrike's Falcon Next-Gen SIEM is expanding to support third-party EDR solutions, starting with Microsoft Defender, to enable organizations to modernize their SOC without replacing existing endpoint agents and improve threat detection across diverse environments.
date: "2026-03-23T00:00:00Z"
severities:
  - medium
tags:
  - siem
  - edr
  - threat-intelligence
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-next-gen-siem-supports-third-party-edr-tools-starting-with-microsoft-defender/
rules:
  - title: Detect Defender Telemetry Ingestion via Falcon Onum
    description: Detects the ingestion of Microsoft Defender telemetry through Falcon Onum, indicating the integration is active.
    platform: sigma
    severity: informational
    tactics:
      - defensive_evasion
    techniques:
      - T1562
    data_sources:
      - webserver
      - linux
  - title: Falcon SIEM Federated Search Activity
    description: Detects attempts to execute federated searches within Falcon SIEM across multiple data sources.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CrowdStrike is enhancing its Falcon Next-Gen SIEM to incorporate third-party Endpoint Detection and Response (EDR) solutions, initially supporting Microsoft Defender. This integration aims to provide organizations with a unified security operations center (SOC) view without requiring the replacement of existing endpoint agents. By integrating data from multiple sources, including Microsoft Defender, Falcon Next-Gen SIEM seeks to address the challenges posed by fragmented security systems and…
