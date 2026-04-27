---
title: ShareFile Storage Zones Controller Unauthenticated Configuration Access and Potential RCE (CVE-2026-2699)
slug: 2026-04-sharefile-szc-rce
description: An unauthenticated attacker can access restricted configuration pages in Customer Managed ShareFile Storage Zones Controller (SZC), leading to system configuration changes and potential remote code execution.
date: "2026-04-02T14:16:27Z"
severities:
  - critical
tags:
  - sharefile
  - storage-zones-controller
  - rce
  - cve-2026-2699
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1020
    technique_name: Automated Execution
references:
  - https://docs.sharefile.com/en-us/storage-zones-controller/5-0/security-vulnerability-feb26
  - https://github.com/watchtowrlabs/watchTowr-vs-Progress-ShareFile-CVE-2026-2699
ioc_counts:
  email: 1
  url: 2
rules:
  - title: Detect Unauthorized Access to ShareFile SZC Configuration Pages
    description: Detects attempts to access restricted configuration pages in ShareFile Storage Zones Controller without authentication.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
  - title: Detect Suspicious File Uploads to ShareFile SZC
    description: Detects file uploads to ShareFile Storage Zones Controller that may indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1020
    data_sources:
      - webserver
      - windows
rules_count: 2
---

CVE-2026-2699 affects Customer Managed ShareFile Storage Zones Controller (SZC) versions prior to the fix. The vulnerability allows an unauthenticated attacker to bypass access controls and directly access restricted configuration pages. This unauthorized access can lead to malicious actors changing system settings, potentially installing backdoors, or executing arbitrary code remotely. The vulnerability was reported to Progress Software Corporation and assigned a CVSS v3.1 base score of 9.8…
