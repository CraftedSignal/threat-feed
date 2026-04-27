---
title: CrowdStrike Falcon Data Security Prevents Data Exfiltration
slug: 2026-03-falcon-data-security
description: CrowdStrike's Falcon Data Security helps organizations understand sensitive data, track its movement, and prevent data theft across endpoints, browsers, SaaS applications, cloud services, GenAI tools, and agentic workflows by leveraging advanced classification and real-time monitoring.
date: "2026-03-28T09:18:29Z"
severities:
  - high
tags:
  - data-exfiltration
  - dlp
  - cloud-security
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-data-security-secures-data-wherever-it-lives-and-moves/
rules:
  - title: Detect Suspicious Data Compression Before Exfiltration
    description: Detects potential data exfiltration attempts by monitoring for the execution of compression tools (e.g., zip, rar, 7z) commonly used to package data before exfiltration.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Data Upload via Web Browser to Cloud Storage Services
    description: Detects potential data exfiltration attempts by monitoring network connections from web browsers to known cloud storage services.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CrowdStrike Falcon Data Security is a new product designed to protect sensitive data across diverse environments. The product aims to address the challenge of securing data as it is created, accessed, transformed, and shared across endpoints, browsers, SaaS applications, cloud services, GenAI tools, and agentic workflows. Falcon Data Security focuses on discovering, classifying, and defending sensitive data against various risks, including employee mistakes and malicious actors using valid…
