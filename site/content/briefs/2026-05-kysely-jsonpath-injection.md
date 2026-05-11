---
title: Kysely JSON-path Injection Vulnerability
slug: 2026-05-kysely-jsonpath-injection
description: A JSON-path traversal injection vulnerability exists in Kysely versions prior to 0.28.16, allowing attackers to traverse JSON sub-fields outside the intended scope, potentially leading to unauthorized read and write access to sensitive data in MySQL, PostgreSQL, and SQLite databases due to insufficient sanitization of JSON-path metacharacters in the `JSONPathBuilder.key()` and `.at()` functions.
date: "2026-05-11T19:42:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kysely:kysely:*:*:*:*:*:node.js:*:*
tags:
  - jsonpath
  - injection
  - kysely
  - cwe-89
  - cwe-915
  - cwe-1284
vendors:
  - MySQL
  - PostgreSQL
  - SQLite
products:
  - MySQL
  - PostgreSQL
  - SQLite
  - kysely
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-32763
    cvss: 8.2
    epss: 0.0002
references:
  - https://github.com/advisories/GHSA-pv5w-4p9q-p3v2
  - https://github.com/advisories/GHSA-wmrf-hv6w-mr66
rules:
  - title: Detect Kysely JSON-path Injection Attempts
    description: Detects Kysely JSON-path injection attempts by identifying suspicious characters in JSON path queries.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Kysely JSON-path Wildcard Injection (MySQL/PostgreSQL)
    description: Detects Kysely JSON-path wildcard injection attempts specifically targeting MySQL and PostgreSQL `->$` operators, which allow wildcard recursion
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A JSON-path injection vulnerability has been identified in Kysely, a TypeScript SQL query builder, affecting MySQL, PostgreSQL `->$`/`->>$`, and SQLite dialects. The vulnerability stems from insufficient sanitization of JSON-path metacharacters (`.`, `[`, `]`, `*`, `**`, `?`) in the `JSONPathBuilder.key()` and `.at()` functions.  Specifically, Kysely 0.28.12 added a `sanitizeStringLiteral()` call inside `DefaultQueryCompiler.visitJSONPathLeg` (commit `0a602bf`, PR #1727) to fix CVE-2026-32763 (`GHSA-wmrf-hv6w-mr66`), however this fix only escapes single quotes, and not the other JSON-path metacharacters. This allows attackers to traverse from the intended key into sibling and child fields, potentially exposing sensitive data that was intended to be private. The vulnerability can be exploited even in type-safe code where the JSON column is shaped like `Record<string, T>`. The affected code resides primarily in `src/query-compiler/default-query-compiler.ts` and `src/query-builder/json-path-builder.ts`.

## Attack Chain

1. An attacker identifies a Kysely-based application that uses `eb.ref(col, '->$').key(input)` or `.at(input)` to construct JSON path queries.
2. The application's JSON column is typed as `Record<string, T>`, which allows attacker-controlled input to be passed to `.key()` without triggering type errors.
3. The attacker crafts a malicious input string containing JSON-path metacharacters (e.g., `nick.secret_field`, `*`, `[].secret]`).
4. The attacker-controlled input is passed to the `key()` or `at()` function, which constructs a JSON path expression.
5. The `visitJSONPathLeg` function in `default-query-compiler.ts` is called to compile the JSON path.
6. The `sanitizeStringLiteral` function is called on the attacker-controlled input, but it only escapes single quotes and does not neutralize other JSON-path metacharacters.
7. The compiled SQL query, containing the unescaped metacharacters, is executed against the database.
8. The database interprets the metacharacters as JSON path operators, allowing the attacker to access or modify unintended JSON sub-fields, leading to data disclosure or unauthorized modification of data.

## Impact

Successful exploitation of this vulnerability can lead to unauthorized access to sensitive data stored within JSON columns, including SSNs, tokens, and admin flags. In MySQL and PostgreSQL, attackers can use wildcards to enumerate all values at the current depth or recursively across the entire document. In update statements, attackers can modify nested fields, potentially escalating privileges or altering application behavior. The vulnerability bypasses previous hardening attempts, making applications that relied on the earlier fix vulnerable again. The impact is significant for applications that handle sensitive data in JSON format and expose JSON path queries to user input.

## Recommendation

*   Apply a dedicated `sanitizeJSONPathLeg` function that only emits a known-good character set per leg type and rejects everything else as described in the advisory.
*   Deploy the Sigma rule "Detect Kysely JSON-path Injection Attempts" to monitor for attempted exploitation by detecting path traversal metacharacters.
*   Audit all code that uses `eb.ref(col, '->$').key(input)` or `.at(input)` to ensure that user-supplied input is properly validated and sanitized.
*   Upgrade to Kysely version 0.28.17 (or later) once it is released to incorporate the necessary security fixes.
*   Review database logs for suspicious JSON path queries containing unexpected metacharacters (e.g. `.` `*` `[]`) targeting JSON columns to identify potential exploitation attempts.
