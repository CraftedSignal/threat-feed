---
title: PraisonAI Multiple Backends Vulnerable to SQL Injection via Unvalidated Table Prefix
slug: 2026-04-praisonai-sqli
description: PraisonAI is vulnerable to SQL injection across nine database backends due to unsanitized `table_prefix` parameters, and in PostgreSQL due to an unsanitized `schema` parameter, enabling arbitrary SQL execution.
date: "2026-04-18T12:00:00Z"
type: coverage
types:
  - coverage
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

PraisonAI, a software application, contains a critical SQL injection vulnerability affecting nine of its conversation store backends, including MySQL, PostgreSQL, and others. The vulnerability stems from the improper handling of the `table_prefix` parameter, which is passed directly into SQL queries without adequate validation. Specifically, backends such as MySQL, PostgreSQL, async SQLite/MySQL/PostgreSQL, Turso, SingleStore, Supabase, and SurrealDB are affected. In addition, the PostgreSQL backend is vulnerable due to the unvalidated `schema` parameter. This flaw allows an attacker to inject arbitrary SQL commands, potentially gaining unauthorized access to sensitive data. The incomplete fix for CVE-2026-40315 only addressed the SQLite backend, leaving other backends exposed. This vulnerability exists in PraisonAI versions 4.5.148 and earlier, as well as PraisonAI Agents versions 1.6.7 and earlier.

## Attack Chain

1. An attacker identifies a PraisonAI instance where the `table_prefix` or `schema` (PostgreSQL) parameter is derived from external input (e.g., API request, user-modifiable configuration).
2. The attacker crafts a malicious `table_prefix` or `schema` string containing SQL injection payload (e.g., "x'; DROP TABLE users; --").
3. The attacker injects the malicious `table_prefix` or `schema` via the vulnerable input vector.
4. The PraisonAI application receives the crafted `table_prefix` or `schema` and incorporates it into a dynamically generated SQL query without proper sanitization.
5. The application executes the malicious SQL query against the database.
6. The attacker's injected SQL commands are executed, potentially allowing them to read, modify, or delete data within the database.
7. The attacker gains unauthorized access to sensitive data, such as user credentials, financial information, or other confidential data.
8. The attacker may escalate privileges, compromise other systems, or perform further malicious activities within the affected environment.

## Impact

Successful exploitation of this vulnerability enables attackers to execute arbitrary SQL commands, potentially leading to complete database compromise. The attacker can read sensitive data, modify existing records, inject malicious code, or even drop entire tables. This can result in significant data loss, financial damage, and reputational harm for affected organizations. This vulnerability is exploitable in any deployment where the `table_prefix` is derived from external input, such as in multi-tenant setups or API-driven configurations. The PostgreSQL `schema` parameter provides an additional injection point, further expanding the attack surface.

## Recommendation

*   Apply input validation and sanitization to the `table_prefix` parameter in all database backends, mirroring the fix implemented for `sqlite.py` as described in the overview.
*   Apply input validation and sanitization to the `schema` parameter in the PostgreSQL backend, as noted in the overview.
*   Deploy the Sigma rule `Detect Malicious Table Prefix` to detect attempts to exploit this vulnerability in MySQL and PostgreSQL backends, as detailed below.
*   Upgrade PraisonAI to a version that includes proper input validation for `table_prefix` and `schema` parameters, targeting versions later than 4.5.148 for PraisonAI and later than 1.6.7 for PraisonAI Agents.
