---
brief_id: brief-2026-10-22-woothemes-diarise-file-read
event_id: brief-2026-10-22-woothemes-diarise-file-read
revision: 1
activity_at: "2026-10-22T14:15:00Z"
title: 'WooThemes Diarise: Arbitrary file read vulnerability (CVE-2019-25779)'
slug: 2026-10-woothemes-diarise-file-read
description: WooThemes Diarise versions through 1.5.9 are vulnerable to an arbitrary file read exploit in download.php, allowing unauthenticated attackers to retrieve sensitive system files via a crafted calendar parameter.
date: "2026-10-22T14:15:00Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Ready for deployment
cpes:
  - cpe:2.3:a:woothemes:diarise:*:*:*:*:*:*:*:*
tags:
  - web-application
  - file-read
  - lfi
vendors:
  - WooThemes
products:
  - Diarise (<= 1.5.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: WooThemes Diarise through 1.5.9 contains a file read vulnerability that allows unauthenticated attackers to read arbitrary files through the calendar parameter of download.php.
    confidence_band: high
cves:
  - id: CVE-2019-25779
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25779
rules:
  - title: Detect CVE-2019-25779 Exploitation Attempt - Arbitrary File Read
    description: Detects exploitation attempts against CVE-2019-25779 by monitoring for file:// scheme usage in the calendar parameter of download.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to detect CVE-2019-25779 exploitation attempts
      owner: Detection Engineering
      due: 24h
      evidence: Rule developed based on NVD vulnerability details
  mitigation_plan:
    - priority: immediate
      action: Inventory all sites running WooThemes Diarise; remove or disable if not required
      owner: IT Operations
      addresses: CVE-2019-25779
      evidence: Vulnerability in unauthenticated file read
---

WooThemes Diarise through version 1.5.9 contains an arbitrary file read vulnerability. An unauthenticated attacker can exploit this via the calendar parameter in download.php by passing a file:// scheme path. This allows for the disclosure of sensitive files such as /etc/passwd. Active exploitation of this vulnerability was documented by the Shadowserver Foundation starting on 2023-10-19.

## Impact
Successful exploitation allows unauthenticated remote attackers to read arbitrary files from the underlying server filesystem, potentially leading to the disclosure of configuration files, credentials, or system information.

## Recommendation
* Update WooThemes Diarise to the latest version if available, or remove the plugin if it is not business-critical.
* Monitor web server access logs for requests to download.php where the calendar parameter contains a file scheme URI.
* Restrict access to web application files and sanitize all user-supplied input used in file operations.
