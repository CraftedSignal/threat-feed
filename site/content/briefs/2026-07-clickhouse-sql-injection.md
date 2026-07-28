---
title: SQL Injection Vulnerability in @hypequery/clickhouse Allows Arbitrary SQL Execution
slug: 2026-07-clickhouse-sql-injection
description: A SQL injection vulnerability exists in the `escapeValue()` function of the `@hypequery/clickhouse` library, affecting versions prior to 2.0.2, allowing attackers to leverage a trailing backslash in user-controlled query parameters to bypass escaping mechanisms, leading to arbitrary SQL execution against ClickHouse databases.
date: "2026-07-28T22:21:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - vulnerability
  - npm
  - clickhouse
  - supply-chain
vendors:
  - hypequery
products:
  - '@hypequery/clickhouse (< 2.0.2)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers who can control parameter values can inject arbitrary SQL by using a trailing backslash to escape the closing quote.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A SQL injection vulnerability exists in the `escapeValue()` function used for parameter substitution.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6wcc-39rp-hh9p
---

A critical SQL injection vulnerability, identified as CVE-2026-54658, has been discovered in the `@hypequery/clickhouse` npm package, specifically within its `escapeValue()` function. This flaw affects all versions of the library prior to 2.0.2. Attackers can exploit this by providing user-controlled input containing a trailing backslash character (`\`) followed by arbitrary SQL code when interacting with an application that uses the vulnerable library to query a ClickHouse database. The `escapeValue()` function's improper handling of backslashes before escaping single quotes allows the attacker's malicious SQL to be injected and executed. This can lead to unauthorized data access, modification, or deletion, posing a significant threat to data integrity and confidentiality for organizations using this package. The vulnerability highlights a supply chain risk for applications relying on third-party libraries for database interactions.

## Attack Chain

1. An attacker identifies a web application or service that utilizes the `@hypequery/clickhouse` library to interact with a ClickHouse database.
2. The attacker discovers an input field or parameter in the application that processes user-supplied values, which are subsequently passed into a SQL query via the vulnerable `escapeValue()` function.
3. The attacker crafts a malicious input string that contains legitimate data followed by a backslash (`\`) and then their arbitrary SQL injection payload (e.g., `user_input_data\' OR 1=1--`).
4. When the application uses `@hypequery/clickhouse` to prepare the query, the `escapeValue()` function is called on the malicious input.
5. Due to the flaw in versions prior to 2.0.2, the trailing backslash in the attacker's input escapes the legitimate single quote character that the library would normally add to close the string.
6. This mis-escaping causes the attacker's SQL injection payload (e.g., `OR 1=1--`) to be interpreted as part of the SQL query itself, rather than as literal string data.
7. The application then executes the manipulated SQL query against the backend ClickHouse database.
8. The arbitrary SQL code is executed on the ClickHouse database, allowing the attacker to perform actions such as data exfiltration, unauthorized data modification, or other database manipulation, depending on the attacker's payload and the database user's privileges.

## Impact

Successful exploitation of CVE-2026-54658 allows attackers to achieve arbitrary SQL execution within the context of the affected ClickHouse database. This can lead to severe consequences, including full compromise of the database's data, such as exfiltration of sensitive information, modification of existing records, or deletion of critical data. Organizations whose applications rely on `@hypequery/clickhouse` are at risk of significant data breaches and operational disruption if their user-facing inputs are not adequately protected. No specific victim counts or sectors were identified in the advisory, but any application using the vulnerable library is exposed.

## Recommendation

* Upgrade `@hypequery/clickhouse` to version 2.0.2 or later immediately to apply the patch for CVE-2026-54658.
* Review applications using `@hypequery/clickhouse` for proper input validation on all user-controlled parameters that are passed into database queries.
