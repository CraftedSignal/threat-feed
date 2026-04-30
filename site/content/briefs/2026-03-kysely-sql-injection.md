---
title: SQL Injection Vulnerability in Kysely TypeScript Library (CVE-2026-33442)
slug: 2026-03-kysely-sql-injection
description: Kysely versions 0.28.12 and 0.28.13 are vulnerable to SQL injection due to insufficient escaping of backslashes in the `sanitizeStringLiteral` method, potentially leading to arbitrary SQL execution on MySQL servers.
date: "2026-03-26T17:16:40Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - kysely
  - cve-2026-33442
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33442
  - https://github.com/kysely-org/kysely/security/advisories/GHSA-fr9j-6mvq-frcv
rules:
  - title: Detect Potential SQL Injection via Backslash-Quote in Web Logs
    description: Detects potential SQL injection attempts exploiting the Kysely vulnerability (CVE-2026-33442) by searching for backslash-quote patterns in web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Potential SQL Injection via Backslash-Quote in Application Logs
    description: Detects potential SQL injection attempts exploiting the Kysely vulnerability (CVE-2026-33442) by searching for backslash-quote patterns in application logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
rules_count: 2
---

Kysely, a type-safe TypeScript SQL query builder, is susceptible to a SQL injection vulnerability identified as CVE-2026-33442. The vulnerability resides in the `sanitizeStringLiteral` method of the query compiler within versions 0.28.12 and 0.28.13. The method inadequately handles backslashes, failing to escape them, while properly escaping single quotes. On MySQL servers configured with the default `BACKSLASH_ESCAPES` SQL mode enabled, this oversight allows an attacker to inject a backslash…
