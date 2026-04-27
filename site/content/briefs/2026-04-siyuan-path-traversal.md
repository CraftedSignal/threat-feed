---
title: SiYuan Path Traversal via Double URL Encoding in `/export/` Endpoint
slug: 2026-04-siyuan-path-traversal
description: SiYuan is vulnerable to path traversal via double URL encoding in the `/export/` endpoint, bypassing an incomplete fix for CVE-2026-30869; an authenticated attacker can exploit this vulnerability to traverse directories and read arbitrary workspace files, including the SQLite database (`siyuan.db`), kernel log, and user documents due to a redundant `url.PathUnescape()` call in `serveExport()`.
date: "2026-04-22T20:55:31Z"
severities:
  - high
tags:
  - path-traversal
  - web-application
  - siYuan
vendors:
  - siyuan
products:
  - siyuan
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-30869
    cvss: 9.3
    epss: 0.00677
references:
  - https://github.com/advisories/GHSA-hjh7-r5w8-5872
ioc_counts:
  url: 1
rules:
  - title: Detect SiYuan Path Traversal Attempt
    description: Detects attempts to exploit the SiYuan path traversal vulnerability by monitoring for double URL encoded characters in requests to the `/export/` endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect SiYuan Database File Access via Export
    description: Detects attempts to access the SiYuan database file via the /export/ endpoint.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

SiYuan is vulnerable to a path traversal vulnerability (CVE-2026-30869) due to a redundant `url.PathUnescape()` call within the `serveExport()` function. The vulnerability exists in versions prior to 3.6.5. This flaw allows an authenticated attacker, including low-privilege users with Publish/Reader roles, to bypass intended security restrictions and access sensitive files stored within the SiYuan workspace. The initial fix attempted with `IsSensitivePath()` proved insufficient as it did not…
