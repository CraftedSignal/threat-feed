---
brief_id: brief-2026-11-18-phishing-iso-in-archive
event_id: brief-2026-11-18-phishing-iso-in-archive
revision: 1
activity_at: "2026-11-18T13:50:51Z"
title: 'Phishing Pattern: ISO Files Opened via Archivers'
slug: 2026-11-phishing-iso-in-archive
description: Threat actors distribute small ISO files within archives as email attachments to bypass security filters and protective measures.
date: "2026-11-18T13:50:51Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - attack.initial-access
  - attack.t1566
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Detects cases in which an ISO files is opened within an archiver like 7Zip or Winrar, which is a sign of phishing as threat actors put small ISO files in archives as email attachments to bypass certain filters and protective measures
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_archiver_iso_phishing.yml
  - https://twitter.com/1ZRR4H/status/1534259727059787783
  - https://app.any.run/tasks/e1fe6a62-bce8-4323-a49a-63795d9afd5d/
rules:
  - title: Phishing Pattern ISO in Archive
    description: Detects cases in which an ISO file is opened within an archiver like 7Zip or Winrar, a technique used by threat actors to bypass filters.
    platform: sigma
    severity: high
    tactics:
      - initial-access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

## Overview
Threat actors distribute small ISO files within archive files as email attachments to bypass security filters and protective measures. This activity can be identified by tracking parent-child process relationships where archival software such as 7-Zip, WinRAR, or PeaZip spawns an ISO-handling utility.

## Attack Chain
- Initial Access: Use of archive files to deliver ISO payloads via email attachments.

## Impact
This technique allows threat actors to bypass filters by embedding ISO files within archives, facilitating the delivery of malicious payloads.

## Recommendation
Monitor process creation events for instances where WinRAR (Winrar.exe), 7-Zip (7zFM.exe), or PeaZip (peazip.exe) launch ISO-related processes including isoburn.exe, PowerISO.exe, or ImgBurn.exe. Note that this may result in false positives if a user legitimately opens an ISO file from an archive.
