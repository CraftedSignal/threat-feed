---
title: CrowdStrike Falcon Cloud Security Advances CNAPP with Adversary-Informed Risk Prioritization
slug: 2026-03-cnapp-advancements
description: CrowdStrike Falcon Cloud Security enhances its CNAPP capabilities, incorporating adversary intelligence to prioritize cloud risks based on threat actor behavior, particularly focusing on groups like LABYRINTH CHOLLIMA and SCATTERED SPIDER, to enable security teams to understand and remediate cloud exposures more effectively.
date: "2026-03-30T06:43:41Z"
severities:
  - medium
actors:
  - LABYRINTH CHOLLIMA, SCATTERED SPIDER
tags:
  - cloud-security
  - cnapp
  - threat-intelligence
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Standard Permission Groups Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Processes Accessing Cloud Resources with Unusual User Agent
    description: Detects processes accessing cloud resources (e.g., AWS S3, Azure Blob Storage, Google Cloud Storage) with unusual user agents, potentially indicating unauthorized access or exploitation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1589.002
    data_sources:
      - network_connection
      - windows|linux|macos
  - title: Detect Overly Permissive Cloud Storage Access
    description: Detects instances where cloud storage resources (e.g., AWS S3 buckets, Azure Blob containers) are configured with overly permissive access policies, potentially leading to data breaches.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1530
    data_sources:
      - webserver
      - linux|windows
rules_count: 2
---

CrowdStrike has enhanced its Falcon Cloud Security with new CNAPP (Cloud-Native Application Protection Platform) capabilities designed to provide more proactive and context-aware cloud security. These advancements address limitations in current CNAPP solutions, which often lack visibility into business applications, ignore adversary behavior, and result in endless triage due to a lack of causality information. The new features, including Application Explorer and adversary-informed risk…
