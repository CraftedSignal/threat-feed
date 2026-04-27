---
title: CrowdStrike CNAPP Enhancements for Adversary-Informed Risk Prioritization
slug: 2026-03-crowdstrike-cnapp
description: CrowdStrike's enhanced Cloud Native Application Protection Platform (CNAPP) improves risk prioritization by incorporating threat intelligence from groups like LABYRINTH CHOLLIMA and SCATTERED SPIDER, providing context on application-infrastructure dependencies, and identifying configuration changes leading to exposure.
date: "2026-03-30T06:46:07Z"
severities:
  - medium
actors:
  - LABYRINTH CHOLLIMA / SCATTERED SPIDER
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
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1530
    technique_name: Exploitation of Cloud Vulnerabilities
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Cloud Metadata Service Access
    description: Detects access to cloud metadata services, which can be an early sign of reconnaissance by threat actors in cloud environments.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - network_connection
      - cloudtrail
  - title: Detect Overly Permissive Storage Access
    description: Detects storage resource access with overly permissive configurations, potentially exposing sensitive data to unauthorized access.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

CrowdStrike has enhanced its CNAPP offering by incorporating adversary-informed risk prioritization. This update addresses limitations in existing CNAPP solutions, which often lack visibility into business applications, ignore specific adversary behaviors, and result in endless triage. The enhanced CNAPP aims to provide security teams with the context needed to understand cloud risks, prioritize remediation efforts, and accelerate the transition from detection to action. A key component…
