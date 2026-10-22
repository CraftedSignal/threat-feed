---
brief_id: brief-2026-10-22-jetbackup-symlink-rce
event_id: brief-2026-10-22-jetbackup-symlink-rce
revision: 2
activity_at: "2026-10-22T22:18:10Z"
revision_history:
  - revision: 2
    at: "2026-10-22T22:18:10Z"
    checksum: sha256:2fb46302d0d433ff34bca60da34dbc0e3085cb5920d0889b70b0d9d7a31be007
    summary: poc_available
    changed_fields:
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=0786BC54-2647-5D7E-AFF1-C5E7C0BD2700&utm_source=rss&utm_medium=rss
title: 'JetBackup for WordPress: Arbitrary file write via symlink (CVE-2026-104068)'
slug: 2026-10-jetbackup-symlink-rce
description: The JetBackup WordPress plugin before 3.1.24.10 is vulnerable to an arbitrary file write attack via malicious symbolic links in backup archives, allowing authenticated administrators to achieve remote code execution.
date: "2026-10-22T20:27:41Z"
lastmod: "2026-10-22T22:17:23Z"
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
  validation_status: Ready for production; requires patching of the affected plugin.
cpes:
  - cpe:2.3:a:jetbackup:jetbackup:*:*:*:*:*:wordpress:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=0786BC54-2647-5D7E-AFF1-C5E7C0BD2700&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - vulnerability
  - rce
vendors:
  - JetBackup
products:
  - JetBackup (< 3.1.24.10)
cves:
  - id: CVE-2026-104068
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104068
  - https://sploitus.com/exploit?id=0786BC54-2647-5D7E-AFF1-C5E7C0BD2700&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade JetBackup for WordPress to 3.1.24.10 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-104068 vulnerability patch availability
  mitigation_plan:
    - priority: immediate
      action: Upgrade JetBackup to version 3.1.24.10
      owner: IT Operations
      addresses: CVE-2026-104068
      evidence: NVD advisory for CVE-2026-104068
updates:
  - at: "2026-10-22T22:17:23Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=0786BC54-2647-5D7E-AFF1-C5E7C0BD2700&utm_source=rss&utm_medium=rss
---

JetBackup for WordPress versions prior to 3.1.24.10 contain a vulnerability where the plugin fails to sanitize symbolic links present within backup archives during the import and restore process. An authenticated WordPress administrator can craft a backup file containing a symlink that points to arbitrary locations on the host filesystem. When processed, the plugin follows these links, allowing the attacker to overwrite sensitive files or write arbitrary content to locations outside the intended restore directory, potentially resulting in server-side code execution.

## Impact

Successful exploitation allows an authenticated administrator to gain arbitrary file write capabilities on the underlying server, which can be leveraged to achieve remote code execution.

## Recommendation

* Update the JetBackup plugin for WordPress to version 3.1.24.10 or later immediately.
* Audit administrative user accounts within the WordPress environment to ensure that access is restricted only to trusted personnel, as this vulnerability requires administrator privileges.
* Monitor web server logs and filesystem activity for suspicious file write attempts or modifications occurring within the WordPress directory structure during manual or automated backup/restore operations.
