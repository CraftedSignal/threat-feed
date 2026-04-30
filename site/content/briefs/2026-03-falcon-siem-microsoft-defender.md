---
title: CrowdStrike Falcon Next-Gen SIEM Supports Third-Party EDR Tools
slug: 2026-03-falcon-siem-microsoft-defender
description: CrowdStrike's Falcon Next-Gen SIEM now supports third-party EDR solutions, starting with Microsoft Defender, to extend AI-native SOC capabilities without replacing existing endpoint agents.
date: "2026-03-29T14:22:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - siem
  - edr
  - threat-intelligence
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1530
    technique_name: Data Source Discovery
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-next-gen-siem-supports-third-party-edr-tools-starting-with-microsoft-defender/
rules:
  - title: Detecting ExtraHop Network Traffic via Federated Search
    description: This rule detects network traffic patterns identified by ExtraHop through federated search capabilities.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - network_connection
      - windows
  - title: Detecting Amazon S3 Bucket Access via Athena Federated Query
    description: This rule detects access to Amazon S3 buckets using Athena federated query capabilities.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

CrowdStrike Falcon Next-Gen SIEM is expanding its capabilities to integrate with third-party EDR solutions, beginning with Microsoft Defender. This allows organizations to modernize their Security Operations Center (SOC) without the need to replace existing endpoint agents. The integration addresses the challenge of adversaries exploiting cross-domain gaps across endpoint, identity, network, and cloud environments. Security teams can now investigate across previously fragmented systems. Falcon Onum, natively embedded within the Falcon platform, delivers a unified experience for real-time data pipelines, enabling ingestion, filtering, enrichment, and routing of data in motion. This enhancement aims to reduce noise and improve data fidelity before it reaches downstream systems, leading to faster detection and more efficient investigations.

## Attack Chain

1. Adversary exploits cross-domain gaps across endpoint, identity, network, and cloud environments.
2. Attack spans across different tools and environments, creating fragmented investigation scenarios for security teams.
3. Legacy SIEMs impose a "data tax" for full ingestion, resulting in slower detection.
4. Siloed tools create blind spots and disconnected workflows, hindering effective response.
5. Falcon Onum ingests data, filters noise, enriches telemetry, and routes data in real-time to reduce storage costs.
6. High-signal data is prioritized and routed to Falcon Next-Gen SIEM for active investigations.
7. Remaining data is efficiently archived to cost-effective external data stores like Amazon S3 via Athena.
8. Security teams can then investigate across the disparate data sources through federated search, operationalizing threat intelligence at scale.

## Impact

The lack of integrated security tools leads to slower detection and delayed incident response, making it harder for SOC teams to keep pace with modern threats. Organizations face increased operational costs due to duplicated data and the need for extensive data ingestion. By integrating third-party EDR solutions, CrowdStrike aims to provide faster detection, more efficient investigations, and a stronger foundation for AI-driven security operations.

## Recommendation

*   Deploy Falcon Next-Gen SIEM and configure it to ingest Microsoft Defender telemetry to unify detection, investigation, and response without changing endpoint deployments.
*   Leverage Falcon Onum to filter and enrich data in real-time, reducing noise and storage costs, as mentioned in the **Overview**.
*   Utilize federated search capabilities to investigate across live, network, and archived data sources (Falcon LogScale, ExtraHop, Amazon S3 via Athena) as described in the **Attack Chain**.
*   Explore the Third-Party Indicator Management feature to ingest, enrich, and manage external indicators of compromise.
