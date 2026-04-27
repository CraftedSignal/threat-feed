---
title: CrowdStrike Falcon CNAPP Adversary-Informed Risk Prioritization
slug: 2026-03-cnapp-risk-prioritization
description: CrowdStrike Falcon Cloud Security introduces new CNAPP capabilities including Application Explorer and adversary intelligence to prioritize cloud risks based on threat actor behavior, enabling security teams to focus on documented intrusion patterns by groups like LABYRINTH CHOLLIMA and SCATTERED SPIDER.
date: "2026-03-30T06:19:01Z"
severities:
  - high
actors:
  - LABYRINTH CHOLLIMA, SCATTERED SPIDER
tags:
  - cloud-security
  - cnapp
  - threat-intelligence
  - risk-prioritization
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1535
    technique_name: Unprotected Credentials
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Suspicious Cloud Resource Enumeration
    description: Detects potential reconnaissance activity through excessive API calls.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Cloud Storage Access by Unusual Process
    description: Detects access to cloud storage buckets by processes not typically associated with cloud operations.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1535
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

CrowdStrike has enhanced its Falcon Cloud Security with new CNAPP capabilities designed to improve risk prioritization in cloud environments. This update focuses on addressing the limitations of current CNAPP solutions, which often lack visibility into business applications, ignore adversary behavior, and result in endless triage due to a lack of context around configuration changes. The new features, including Application Explorer and adversary intelligence integration, aim to provide security…
