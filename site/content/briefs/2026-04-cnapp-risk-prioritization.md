---
title: CrowdStrike CNAPP Adds Adversary-Informed Risk Prioritization
slug: 2026-04-cnapp-risk-prioritization
description: CrowdStrike's CNAPP enhancements prioritize cloud risks based on adversary behavior, application context, and configuration change tracking to reduce breach likelihood.
date: "2026-03-29T06:52:03Z"
severities:
  - medium
actors:
  - LABYRINTH CHOLLIMA, SCATTERED SPIDER
tags:
  - cnapp
  - cloud-security
  - risk-prioritization
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1556
    technique_name: Credentials from Password Stores
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Cloud Resource Access by Uncommon Process
    description: Detects access to cloud resources by processes not typically associated with cloud management, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1556.006
    data_sources:
      - process_creation
      - windows
  - title: Detect Unusual Cloud CLI Tool Execution Location
    description: Detects execution of cloud CLI tools (aws, azure, gcloud) from unusual locations, suggesting potential compromise.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike has enhanced its Cloud Native Application Protection Platform (CNAPP) with new features designed to address the limitations of existing cloud risk assessment approaches. Current CNAPP solutions often lack visibility into the application layer, ignore adversary behavior when prioritizing risks, and struggle to connect risk detections to the configuration changes that introduced them. The updated Falcon Cloud Security aims to bridge these gaps by incorporating application context…
