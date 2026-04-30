---
title: Drizzle ORM SQL Injection Vulnerability (CVE-2026-39356)
slug: 2026-04-drizzle-sql-injection
description: Drizzle ORM versions before 0.45.2 and 1.0.0-beta.20 are vulnerable to SQL injection due to improper escaping of SQL identifiers, allowing attackers to inject malicious SQL code through manipulated input leading to potential data breaches.
date: "2026-04-08T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - drizzle-orm
  - cve-2026-39356
  - typescript
  - orm
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1213
    technique_name: Data from Information Repositories
cves:
  - id: CVE-2026-39356
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39356
rules:
  - title: Detect Drizzle ORM SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting Drizzle ORM by looking for suspicious characters in HTTP request parameters.
    platform: sigma
    severity: high
    tactics:
      - injection
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect Drizzle ORM SQL Injection - Double Quotes
    description: Detects potential SQL injection attempts in Drizzle ORM applications through double quotes in the query string.
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

Drizzle ORM, a TypeScript ORM, contains a SQL injection vulnerability (CVE-2026-39356) in versions prior to 0.45.2 and 1.0.0-beta.20. The vulnerability stems from improper escaping of quoted SQL identifiers within the `escapeName()` implementations. Specifically, embedded identifier delimiters were not properly escaped before being enclosed in quotes or backticks. This allows attackers to inject arbitrary SQL code by manipulating input passed to APIs like `sql.identifier()` or `.as()` which are used to construct SQL identifiers or aliases. Successful exploitation could lead to unauthorized data access, modification, or other database manipulation. Organizations using affected versions of Drizzle ORM are at risk. This issue is resolved in versions 0.45.2 and 1.0.0-beta.20.

## Attack Chain

1.  Attacker identifies an application using a vulnerable version of Drizzle ORM (prior to 0.45.2 or 1.0.0-beta.20).
2.  Attacker locates input fields or API endpoints that utilize `sql.identifier()` or `.as()` to construct SQL queries.
3.  Attacker crafts malicious input containing embedded identifier delimiters (e.g., quotes or backticks) and SQL code.
4.  The application passes the attacker-controlled input to `sql.identifier()` or `.as()` without proper sanitization.
5.  Drizzle ORM's vulnerable `escapeName()` function fails to properly escape the malicious delimiters.
6.  The crafted SQL identifier is incorporated into a larger SQL query.
7.  The application executes the compromised SQL query against the database.
8.  The injected SQL code executes, allowing the attacker to perform unauthorized actions such as data exfiltration or modification.

## Impact

Successful exploitation of CVE-2026-39356 allows attackers to inject arbitrary SQL queries into the application's database interactions. This can lead to sensitive data exposure, unauthorized data modification or deletion, and potentially full database compromise. The severity of the impact depends on the application's database permissions and the sensitivity of the data stored within. Organizations in all sectors utilizing vulnerable Drizzle ORM versions are at risk.

## Recommendation

*   Upgrade Drizzle ORM to version 0.45.2 or 1.0.0-beta.20 to remediate CVE-2026-39356.
*   Implement robust input validation and sanitization on all user-supplied input that is used in SQL queries, even after upgrading Drizzle ORM.
*   Deploy the Sigma rule "Detect Drizzle ORM SQL Injection Attempt" to identify exploitation attempts in your environment.
*   Monitor web server logs for suspicious patterns in HTTP requests indicative of SQL injection attempts (cs-uri-query, cs-uri-stem log fields).
