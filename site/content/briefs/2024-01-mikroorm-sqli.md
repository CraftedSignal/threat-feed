---
title: MikroORM SQL Injection Vulnerability
slug: 2024-01-mikroorm-sqli
description: MikroORM is vulnerable to SQL injection due to improper escaping in identifier-quoting and JSON-path emitters, enabling attackers to inject arbitrary SQL via manipulated strings passed to public ORM APIs, potentially leading to data leaks, modification, and privilege escalation.
date: "2026-05-08T19:17:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - orm
  - mikroorm
vendors:
  - MikroORM
products:
  - '@mikro-orm/sql (<= 7.0.13)'
  - '@mikro-orm/knex (<= 6.6.13)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-cfw5-68c4-ffqp
rules:
  - title: Detect CVE-2026-44680 Exploitation Attempt via Malicious Schema Name
    description: Detects CVE-2026-44680 exploitation attempt via a malicious schema name containing SQL injection characters passed to MikroORM's schema options.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-44680 Exploitation Attempt via Malicious JSON Property Filter
    description: Detects CVE-2026-44680 exploitation attempt via a malicious JSON property filter containing SQL injection characters passed to MikroORM's `em.find` function.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

MikroORM's identifier-quoting helper (`Platform.quoteIdentifier` and the postgres/mssql overrides) and its JSON-path emitters (`Platform.getSearchJsonPropertyKey`, `quoteJsonKey`) did not properly escape characters that delimit the SQL identifier or string-literal context they emit into. This allows for SQL injection vulnerabilities. When application code passes attacker-influenced strings to public ORM APIs that expect an identifier or a JSON-property filter, an attacker can break out of the quoted context and inject arbitrary SQL. This vulnerability affects all SQL dialects supported by MikroORM, specifically versions 7.0.13 and earlier of `@mikro-orm/sql` and versions 6.6.13 and earlier of `@mikro-orm/knex`. The MongoDB driver is not affected.

## Attack Chain

1. The attacker identifies an application using a vulnerable version of MikroORM.
2. The attacker finds an API endpoint that passes user-controlled strings to a vulnerable MikroORM API, such as `em.fork({ schema })` or `em.find(Entity, { jsonCol: { [userKey]: value } })`.
3. The attacker crafts a malicious input string containing SQL injection payloads.
4. This malicious string is passed to MikroORM's `quoteIdentifier` or `getSearchJsonPropertyKey`/`quoteJsonKey` functions without proper escaping.
5. The unescaped string is concatenated into a SQL query.
6. The application executes the crafted SQL query against the database.
7. The attacker gains unauthorized access to data, modifies data, or elevates privileges.
8. The attacker exfiltrates sensitive data or performs other malicious actions.

## Impact

Successful exploitation of this vulnerability could allow an attacker to read from any table/schema the database user has access to, leading to cross-tenant data leaks in multi-tenant deployments. On dialects supporting multi-statement queries (MSSQL, MySQL with multi-statement enabled), attackers can execute additional arbitrary SQL statements, potentially leading to data modification and in-database privilege escalation. Availability could also be impacted through DROP/TRUNCATE statements if the database user has the necessary privileges.

## Recommendation

*   Upgrade MikroORM to version 7.0.14 or later for v7, and 6.6.14 or later for v6, to patch the vulnerability (refer to Patches section in the content).
*   For multi-tenant apps using `em.fork({ schema })` / `wrap().setSchema()` / `qb.withSchema()`, validate the schema name against a strict allowlist (e.g. `^[A-Za-z_][\w$]*$`) before passing it to MikroORM (refer to Workarounds section in the content).
*   For applications that pass `where` / `orderBy` filters from request input, validate every key against the entity's known properties before constructing the filter; do not pass keys containing `.` or `::` from user input (refer to Workarounds section in the content).
*   For applications that allow filtering on JSON columns from request input, validate every JSON sub-key against an allowlist (or against `^[a-zA-Z_][\w]*$`) before passing it to `em.find` (refer to Workarounds section in the content).
