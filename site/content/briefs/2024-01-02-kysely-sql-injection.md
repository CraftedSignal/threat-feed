---
title: Kysely SQL Injection Vulnerability (CVE-2026-33468)
slug: 2024-01-02-kysely-sql-injection
description: A SQL injection vulnerability exists in Kysely versions prior to 0.28.14 due to insufficient backslash escaping in the `DefaultQueryCompiler.sanitizeStringLiteral()` function, potentially allowing attackers to inject arbitrary SQL when using the MySQL dialect, specifically affecting `CreateIndexBuilder.where()` and `CreateViewBuilder.as()` methods.
date: "2026-03-26T17:16:41Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - kysely
  - sql-injection
  - cve-2026-33468
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1505
    technique_name: Server Software Component
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33468
rules:
  - title: Detect Suspicious Kysely Input
    description: Detects potentially malicious input strings containing backslashes followed by single quotes, which could indicate SQL injection attempts in Kysely applications.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempts via URI
    description: Detects SQL injection attempts in the URI of HTTP requests by looking for common SQL injection characters and keywords.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Kysely, a type-safe TypeScript SQL query builder, is susceptible to a SQL injection vulnerability in versions prior to 0.28.14. The vulnerability, identified as CVE-2026-33468, stems from the `DefaultQueryCompiler.sanitizeStringLiteral()` function's failure to properly escape backslashes. This incomplete sanitization, in conjunction with the MySQL dialect's default setting where `NO_BACKSLASH_ESCAPES` is OFF, enables attackers to bypass string literal contexts by injecting arbitrary SQL…
