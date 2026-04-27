---
title: CrowdStrike Falcon Data Security Introduction
slug: 2026-03-falcon-data-security
description: CrowdStrike's Falcon Data Security aims to protect sensitive data by providing visibility into data movement across various environments and preventing data theft.
date: "2026-03-28T08:12:22Z"
severities:
  - medium
tags:
  - data-security
  - data-loss-prevention
  - crowdstrike
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-data-security-secures-data-wherever-it-lives-and-moves/
rules:
  - title: Detect Suspicious SaaS Data Exfiltration via Browser
    description: Detects potential data exfiltration attempts from SaaS applications through web browsers by monitoring file downloads or uploads to suspicious destinations.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Cloud Data Transfer via Command Line
    description: Detects potential data transfer to cloud storage services using command-line tools, which might indicate unauthorized data movement.
    platform: sigma
    severity: low
    tactics:
      - exfiltration
    techniques:
      - T1530
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike has launched Falcon Data Security in March 2026. This solution is designed to help organizations gain enhanced visibility into their sensitive data, track its movement in real time, and prevent data theft across diverse environments including endpoints, browsers, SaaS applications, cloud services, GenAI tools, and agentic workflows. Falcon Data Security aims to address the challenges of modern data security by providing real-time assessment of sensitive data in motion, enabling…
