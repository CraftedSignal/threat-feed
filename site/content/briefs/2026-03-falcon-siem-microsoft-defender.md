---
title: CrowdStrike Falcon Next-Gen SIEM Supports Third-Party EDR Tools
slug: 2026-03-falcon-siem-microsoft-defender
description: CrowdStrike's Falcon Next-Gen SIEM now supports third-party EDR solutions, starting with Microsoft Defender, to extend AI-native SOC capabilities without replacing existing endpoint agents.
date: "2026-03-29T14:22:47Z"
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

CrowdStrike Falcon Next-Gen SIEM is expanding its capabilities to integrate with third-party EDR solutions, beginning with Microsoft Defender. This allows organizations to modernize their Security Operations Center (SOC) without the need to replace existing endpoint agents. The integration addresses the challenge of adversaries exploiting cross-domain gaps across endpoint, identity, network, and cloud environments. Security teams can now investigate across previously fragmented systems. Falcon…
