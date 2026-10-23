---
brief_id: brief-2026-10-22-laravel-tokenguard-bypass
event_id: brief-2026-10-22-laravel-tokenguard-bypass
revision: 2
activity_at: "2026-10-23T23:02:41Z"
revision_history:
  - revision: 2
    at: "2026-10-23T23:02:41Z"
    checksum: sha256:8f762aa35cbd70e5946c0a673172a49799a6c1f5da8fc01fedc1856a970e47bf
    summary: new vendor
    changed_fields:
      - affected_vendors
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/laravel-tokenguard-auth-bypass-cve-2026-114509
title: 'Laravel Framework: Authentication Bypass (CVE-2026-114509)'
slug: 2026-10-laravel-tokenguard-bypass
description: A critical authentication bypass vulnerability exists in the Laravel token guard driver due to improper handling of JSON array input, allowing unauthorized access when using MySQL/MariaDB.
date: "2026-10-22T07:48:39Z"
lastmod: "2026-10-23T23:02:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
tags:
  - laravel
  - authentication-bypass
  - cve-2026-114509
vendors:
  - Laravel
cves:
  - id: CVE-2026-114509
    epss: 0.00403
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=56B2A357-DC57-5411-9397-46C27E16A352
  - https://github.com/laravel/framework/security/advisories/GHSA-f9x3-7vq9-cph6
  - https://sploitus.com/exploit?id=56B2A357-DC57-5411-9397-46C27E16A352&utm_source=rss&utm_medium=rss
  - https://pwn.watch/i/laravel-tokenguard-auth-bypass-cve-2026-114509
  - https://github.com/advisories/GHSA-f9x3-7vq9-cph6
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114509
  - https://github.com/laravel/framework/releases/tag/v12.68.0
  - https://github.com/laravel/framework/releases/tag/v13.29.0
updates:
  - at: "2026-10-23T23:02:10Z"
    level: L1
    summary: new vendor
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/laravel-tokenguard-auth-bypass-cve-2026-114509
---

A public exploit has been published for CVE-2026-114509, a critical (CVSS 9.2) authentication bypass vulnerability in the Laravel `token` guard driver. The vulnerability allows an unauthenticated attacker to bypass authentication via JSON array injection (e.g., `{"api_token": [0]}`) when using a MySQL or MariaDB database. The application's failure to validate the input type combined with MySQL's implicit type coercion allows the bypass. PostgreSQL and SQLite are not affected.
