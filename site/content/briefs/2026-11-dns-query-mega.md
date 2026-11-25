---
brief_id: brief-2026-11-25-dns-query-mega
event_id: brief-2026-11-25-dns-query-mega
revision: 1
activity_at: "2026-11-25T16:21:25Z"
title: DNS Client Queries to MEGA Cloud Storage
slug: 2026-11-dns-query-mega
description: This detection targets DNS queries for subdomains associated with the MEGA cloud storage platform as observed in Windows DNS Client event logs.
date: "2026-11-25T16:21:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  likelihood: likely
tags:
  - exfiltration
  - dns
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    subtechnique_id: T1567.002
    subtechnique_name: Exfiltration to Cloud Storage
    evidence: Detects DNS queries for subdomains related to MEGA sharing website
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_client/win_dns_client_mega_nz.yml
  - https://www.nccgroup.com/research/detecting-rclone-an-effective-tool-for-exfiltration/
rules:
  - title: Detect DNS Queries to MEGA Hosting Service
    description: Detects DNS queries for subdomains related to MEGA sharing website.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - dns_query
      - windows
      - dns-client
rules_count: 1
---

## Overview

This brief documents detection logic for monitoring outbound DNS traffic to the MEGA cloud storage platform (mega.co.nz) using the Windows DNS Client operational log. 

## Attack Chain

- The detection identifies DNS resolution requests for specific subdomains associated with the MEGA storage service.

## Impact

- Potential identification of endpoints communicating with the MEGA cloud storage platform.

## Recommendation

- Enable and collect the Microsoft-Windows-DNS Client Events/Operational log to facilitate detection.
- Deploy the provided Sigma rule to monitor for relevant DNS queries.
