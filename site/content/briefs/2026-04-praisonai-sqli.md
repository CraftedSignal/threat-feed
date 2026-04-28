---
title: PraisonAI Multiple Backends Vulnerable to SQL Injection via Unvalidated Table Prefix
slug: 2026-04-praisonai-sqli
description: PraisonAI is vulnerable to SQL injection across nine database backends due to unsanitized `table_prefix` parameters, and in PostgreSQL due to an unsanitized `schema` parameter, enabling arbitrary SQL execution.
date: "2026-04-18T12:00:00Z"
severities:
  - high
tags:
  - sql-injection
  - praisonai
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40315
    epss: 0.00022
references:
  - https://github.com/advisories/GHSA-rg3h-x3jw-7jm5
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-x783-xp3g-mqhp
rules:
  - title: Detect Malicious Table Prefix
    description: Detects suspicious table prefix values in web requests that may indicate SQL injection attempts against PraisonAI MySQL and PostgreSQL backends.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PraisonAI SQL Injection via Table Name
    description: Detects attempts to inject SQL commands via the table_name parameter, exploiting a vulnerability in SQLiteBackend.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

PraisonAI, a software application, contains a critical SQL injection vulnerability affecting nine of its conversation store backends, including MySQL, PostgreSQL, and others. The vulnerability stems from the improper handling of the `table_prefix` parameter, which is passed directly into SQL queries without adequate validation. Specifically, backends such as MySQL, PostgreSQL, async SQLite/MySQL/PostgreSQL, Turso, SingleStore, Supabase, and SurrealDB are affected. In addition, the PostgreSQL…
