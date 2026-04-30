---
title: NocoBase SQL Injection via Recursive Eager Loading
slug: 2024-01-nocobase-sqli
description: NocoBase versions 2.0.32 and earlier are vulnerable to SQL injection due to string concatenation in the `queryParentSQL()` function, allowing attackers with record creation permissions to inject arbitrary SQL and potentially extract sensitive information or execute commands.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sqli
  - nocobase
  - cve-2026-41640
  - injection
vendors:
  - NocoBase
products:
  - NocoBase
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-4948-f92q-f432
rules:
  - title: Detect NocoBase SQL Injection Attempt in Primary Key
    description: Detects potential SQL injection attempts in NocoBase primary keys by searching for SQL metacharacters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect NocoBase UNION ALL Injection
    description: Detects SQL injection attempts using UNION ALL in NocoBase web requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability exists in NocoBase version 2.0.32 and earlier due to string concatenation in the `queryParentSQL()` function within the `@nocobase/database` core package. The vulnerability stems from how the `queryParentSQL()` function constructs a recursive CTE query by concatenating `nodeIds` instead of using parameterized queries. An attacker with record creation permissions on a tree collection with string-type primary keys can inject arbitrary SQL via a malicious string primary key value in a created record. This injection is triggered when a subsequent request initiates recursive eager loading on that collection. This can lead to confidentiality breaches (extraction of database values including credentials), integrity issues (data manipulation via stacked queries), and availability problems (resource exhaustion). On PostgreSQL with superuser privileges, OS command execution is possible. The vulnerability affects all collections using a tree/adjacency-list structure with string primary keys. The same concatenation pattern also exists in `plugin-field-sort/src/server/sort-field.ts:124`. The vulnerability is tracked as CVE-2026-41640.

## Attack Chain

1. An attacker gains access to the NocoBase application with privileges to create records in a collection.
2. The attacker identifies a "tree" collection that utilizes a string-type primary key.
3. The attacker crafts a malicious primary key string containing SQL injection payload, such as `root') UNION ALL SELECT CAST((SELECT email FROM users LIMIT 1) AS integer)::text, NULL::text WHERE ('1'='1`.
4. The attacker creates a new record in the target collection using the crafted malicious primary key.
5. A subsequent request is made that triggers recursive eager loading on the target collection, specifically when a `BelongsTo` association has `recursively: true` and instances exist, calling the vulnerable `queryParentSQL` function.
6. The `queryParentSQL` function concatenates the malicious primary key into the SQL query without proper sanitization or parameterization.
7. The injected SQL code is executed against the database, allowing the attacker to extract sensitive data via error messages or potentially perform other malicious actions.
8. The attacker retrieves the extracted data from the error messages or through other means, such as direct database access if integrity is compromised.

## Impact

This SQL injection vulnerability can lead to severe consequences. Successful exploitation can result in the unauthorized disclosure of sensitive information, including database credentials and other user data. Attackers can potentially modify data or execute arbitrary commands on the database server, leading to data corruption or system compromise. In the case of PostgreSQL databases with superuser privileges, attackers might gain operating system-level access. The vulnerability affects all collections using tree/adjacency-list structure with string-type primary keys, increasing the attack surface. Confirmed extractions include version information, database names, emails, and password hashes.

## Recommendation

*   Deploy the Sigma rule `Detect NocoBase SQL Injection Attempt in Primary Key` to your SIEM to detect attempts to exploit this vulnerability via malicious primary key values.
*   Apply the suggested fix from the advisory by using parameterized queries in `packages/core/database/src/eager-loading/eager-loading-tree.ts` as referenced in the overview.
*   Apply the same fix to `plugin-field-sort/src/server/sort-field.ts:124` to address the identical concatenation pattern as described in the overview.
*   Validate primary key values at record creation time to reject or escape values containing SQL metacharacters (`'`, `"`, `;`, `--`) in string-type primary key fields, as suggested in the advisory.
