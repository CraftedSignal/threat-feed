---
brief_id: brief-2026-03-23-falcon-siem-defender
event_id: brief-2026-03-23-falcon-siem-defender
revision: 2
activity_at: "2026-03-23T00:00:00Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:c3080265f4b9c35adf7a88f5562d00befcf57585dda7aab35f543072aadf2c31
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: CrowdStrike Falcon Next-Gen SIEM Supports Microsoft Defender
slug: 2026-03-23-falcon-siem-defender
description: CrowdStrike Falcon Next-Gen SIEM now supports third-party EDR solutions, starting with Microsoft Defender, enabling organizations to integrate Microsoft Defender telemetry into Falcon SIEM for unified detection and response.
date: "2026-03-23T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
tags:
  - siem
  - edr
  - microsoft-defender
  - crowdstrike-falcon
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-next-gen-siem-supports-third-party-edr-tools-starting-with-microsoft-defender/
rules:
  - title: Detect Defender Telemetry Ingestion
    description: Detects the ingestion of Microsoft Defender telemetry into Falcon Next-Gen SIEM.
    platform: sigma
    severity: informational
    tactics:
      - defensive_evasion
    data_sources:
      - process_creation
      - windows
  - title: Detect Potential Federated Search Activity
    description: Detects potential federated search activity across multiple data sources.
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

CrowdStrike is expanding its Falcon Next-Gen SIEM to integrate with third-party endpoint detection and response (EDR) solutions, beginning with Microsoft Defender. This integration aims to allow organizations to modernize their Security Operations Center (SOC) without necessarily replacing existing endpoint agents. The integration leverages Falcon Next-Gen SIEM's capabilities, including index-free, petabyte-scale search, AI-driven threat detection, and automation, to provide a unified platform for security operations across diverse environments. This eliminates the need for extensive data ingestion and reduces data silos, improving detection and response times.

## Attack Chain

1.  Adversaries exploit cross-domain gaps across endpoints, identity, network, and cloud environments.
2.  Attacks span across various tools and environments, creating fragmented systems.
3.  Security teams investigate across these disconnected systems, leading to slower detection.
4.  Legacy SIEMs impose a "data tax" for full ingestion, causing delays.
5.  Siloed tools create blind spots and disconnected workflows, hindering effective threat hunting.
6.  Falcon Next-Gen SIEM ingests data from Microsoft Defender via new data pipelines.
7.  Falcon Onum filters and enriches the data in motion to reduce noise.
8.  The unified platform facilitates faster detection, investigation, and response to threats.

## Impact

The lack of integration between security tools can lead to delayed detection and response times, increasing the risk of successful breaches. Organizations struggle to keep pace with modern threats due to fragmented systems and data silos. By integrating Microsoft Defender telemetry into Falcon Next-Gen SIEM, organizations can achieve faster detection, more efficient investigations, and a stronger foundation for AI-driven security operations, mitigating potential data breaches and minimizing the impact of successful attacks.

## Recommendation

*   Deploy the Sigma rule `Detect Defender Telemetry Ingestion` to identify when Microsoft Defender telemetry is being ingested into the Falcon SIEM, providing visibility into this integration. (Sigma Rule)
*   Review Falcon Onum configurations to ensure proper filtering and enrichment of Microsoft Defender telemetry, optimizing data fidelity and reducing storage costs.
*   Utilize federated search capabilities to investigate across live, network (ExtraHop), and archived (Amazon S3 via Athena) data sources within the Falcon platform to correlate events from Microsoft Defender with other security telemetry.
