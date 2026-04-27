---
title: CrowdStrike CNAPP Enhanced with Adversary-Informed Risk Prioritization
slug: 2026-05-cnapp-adversary-risk
description: CrowdStrike enhances its CNAPP capabilities by incorporating adversary intelligence for risk prioritization, application-layer visibility, and runtime analysis, addressing critical gaps in cloud security and enabling faster remediation based on threat actor behavior like LABYRINTH CHOLLIMA and SCATTERED SPIDER.
date: "2026-03-29T07:29:13Z"
severities:
  - high
actors:
  - LABYRINTH CHOLLIMA, SCATTERED SPIDER
tags:
  - cloud_security
  - cnapp
  - threat_intelligence
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1530
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Cloud Account with Excessive Permissions
    description: Detects cloud accounts that have been granted excessive permissions, which can be abused by attackers for lateral movement and data access.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Publicly Accessible Cloud Storage Bucket
    description: Detects when a cloud storage bucket (e.g., AWS S3) is made publicly accessible, potentially exposing sensitive data.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AI Model Exposure
    description: Detects when an application interacts with an external AI model, potentially leading to data exposure to an external service.
    platform: sigma
    severity: low
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

CrowdStrike has advanced its Cloud Native Application Protection Platform (CNAPP) by introducing new capabilities designed to provide security teams with improved context and prioritization for cloud risks. The enhanced CNAPP incorporates Application Explorer for application-layer visibility, allowing a unified view of applications running across cloud and on-premises environments. A key feature is the integration of adversary intelligence, which maps cloud risks to known threat actor profiles…
