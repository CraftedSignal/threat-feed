---
title: Appsmith SQL Injection Vulnerability in FilterDataService
slug: 2024-01-appsmith-sql-injection
description: A SQL injection vulnerability exists in Appsmith's FilterDataServiceCE.java in versions 1.98 and earlier where the dropTable method constructs a SQL DROP TABLE statement using string concatenation with the table name, allowing arbitrary SQL command execution, leading to potential data loss, exfiltration, or modification.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - data-loss
  - appsmith
vendors:
  - Appsmith
products:
  - interfaces
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Injection
references:
  - https://github.com/advisories/GHSA-h8cj-hpmg-636v
rules:
  - title: Detect Appsmith SQL Injection Attempt via DROP TABLE
    description: Detects potential SQL injection attempts in Appsmith by monitoring for suspicious DROP TABLE queries containing injected SQL code.
    platform: sigma
    severity: high
    tactics:
      - injection
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect Appsmith SQL Injection Attempt via Long Table Name
    description: Detects potential SQL injection attempts in Appsmith by monitoring for DROP TABLE queries with unexpectedly long table names, which could indicate injected SQL.
    platform: sigma
    severity: medium
    tactics:
      - injection
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability has been identified in Appsmith's `FilterDataServiceCE.java`, specifically within the `dropTable` method. This flaw affects Appsmith server instances running versions 1.98 and earlier of the `interfaces` package. The vulnerability stems from the direct concatenation of user-supplied table names into a SQL `DROP TABLE` statement without proper sanitization or validation. If an attacker can control the `tableName` argument, they can inject arbitrary SQL commands, potentially leading to unauthorized data manipulation, exfiltration, or data loss. This is particularly concerning in scenarios where the `dropTable` function is exposed through an API or utility accessible to users.

## Attack Chain

1. The attacker identifies an Appsmith instance running a vulnerable version (<= 1.98) of the `interfaces` package.
2. The attacker discovers an endpoint or API that utilizes the `FilterDataServiceCE.java`'s `dropTable` method.
3. The attacker crafts a malicious `tableName` input containing SQL injection payload. Example: `valid_table; DROP TABLE users; --`.
4. The malicious input is passed to the `dropTable` method within `FilterDataServiceCE.java`.
5. The `dropTable` method concatenates the unsanitized input into a SQL `DROP TABLE` statement.
6. The resulting SQL query, containing the injected commands, is executed against the database via the `executeDbQuery` method.
7. The injected SQL commands are executed, potentially dropping tables, modifying data, or exfiltrating sensitive information, depending on the attacker's payload and the database user's permissions.
8. The attacker achieves their objective, such as data loss through arbitrary table deletion.

## Impact

Successful exploitation of this SQL injection vulnerability can have severe consequences. The primary impact is data loss, as attackers can arbitrarily drop tables within the database. Depending on the database user's privileges, attackers may also be able to exfiltrate sensitive data or modify existing data. The vulnerability affects Appsmith server instances. The number of affected instances is currently unknown. However, the potential impact includes unauthorized access to and manipulation of sensitive data, impacting the confidentiality, integrity, and availability of the Appsmith application and its underlying database.

## Recommendation

*   Upgrade Appsmith `interfaces` package to a version greater than 1.98 to patch the SQL injection vulnerability in `FilterDataServiceCE.java`.
*   Implement input validation and sanitization on any endpoints or APIs that utilize the `dropTable` method to prevent SQL injection attacks.
*   Deploy the provided Sigma rule to detect attempts to exploit this SQL injection vulnerability by monitoring for suspicious table names in logs associated with database operations.
