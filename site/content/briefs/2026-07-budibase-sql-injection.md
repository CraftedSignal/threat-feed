---
title: SQL Injection Vulnerability in Budibase MySQL Integration
slug: 2026-07-budibase-sql-injection
description: 'A critical SQL injection vulnerability was discovered in Budibase''s MySQL integration (versions <= 3.38.1) that allows remote attackers to execute arbitrary SQL commands through user input fields due to the `multipleStatements: true` configuration, leading to complete database compromise.'
date: "2026-07-24T21:19:19Z"
lastmod: "2026-07-24T21:31:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - web-application
  - vulnerability
  - nosql-injection
  - data-exfiltration
  - data-destruction
  - application-vulnerability
vendors:
  - Budibase
  - Oracle
products:
  - Budibase Server (<= 3.38.1)
  - MySQL
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A critical SQL injection vulnerability was discovered in Budibase's MySQL integration that allows remote attackers to execute arbitrary SQL commands.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The route requires only `PermissionType.QUERY, PermissionLevel.WRITE` [...] which is available to regular app users
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: Any app user with query write permission can bypass intended query filters to read all documents in a MongoDB collection, including sensitive data belonging to other users or tenants.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Through `deleteMany` queries, attackers can delete all documents matching an injected filter, potentially wiping entire collections.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Because `multipleStatements` is enabled, any statement appended after the backtick break-out executes as a second query in the same round trip. ...allows a malicious table name to break out and inject a second, attacker-controlled statement.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-q6x4-v3qx-85qw
  - https://github.com/advisories/GHSA-qw6m-8fw2-2v64
  - https://github.com/advisories/GHSA-2xgg-r2wc-c5r2
updates:
  - at: "2026-07-24T21:28:31Z"
    level: L2
    summary: 'merged source coverage: Budibase NoSQL Injection via JSON Parameter Interpolation'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-qw6m-8fw2-2v64
  - at: "2026-07-24T21:31:58Z"
    level: L2
    summary: 'merged source coverage: Budibase MySQL Integration Vulnerable to Backtick Injection Leading to Arbitrary SQL Execution'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-2xgg-r2wc-c5r2
---

A critical SQL injection vulnerability, identified in Budibase's MySQL integration in versions up to and including 3.38.1, allows remote attackers to execute arbitrary SQL commands. The vulnerability stems from the MySQL client configuration within Budibase, specifically setting `multipleStatements: true` in the `mysql.ts` file, which permits the execution of multiple SQL statements in a single query. Attackers can leverage this misconfiguration by injecting malicious SQL payloads into user input fields, bypassing typical query sanitization. This vulnerability can lead to severe consequences, including complete database compromise, data destruction, data theft, privilege escalation, and denial of service, posing a significant risk to organizations using affected Budibase deployments. The vulnerability was publicly disclosed by GitHub Security Advisories (GHSA).

## Attack Chain

1. Attacker identifies a public-facing Budibase application utilizing the vulnerable MySQL integration.
2. Attacker crafts a malicious SQL injection payload designed to execute multiple statements.
3. The crafted payload is inserted into a user-controlled input field within the Budibase application (e.g., a search box, login form, or data entry field).
4. The Budibase backend processes the user input, which is then passed directly to the MySQL client configured with `multipleStatements: true`.
5. The MySQL database server executes all statements within the crafted payload, including the legitimate application query and the attacker's malicious commands.
6. Malicious commands execute, leading to potential data exfiltration (e.g., `SELECT INTO OUTFILE`), data modification/destruction (e.g., `DROP TABLE`, `DELETE`), or privilege escalation (e.g., `GRANT ALL PRIVILEGES`).
7. The attacker achieves complete control over the application's underlying database, leading to data compromise.

## Impact

The successful exploitation of this SQL injection vulnerability grants attackers complete control over the Budibase application's underlying MySQL database. This can result in significant damage, including the total destruction of data through `DROP TABLE` or `DELETE` commands, widespread data theft via `SELECT INTO OUTFILE`, and the ability to escalate database privileges. Furthermore, attackers can cause denial of service by disrupting database operations, rendering the application unusable. All data stored within the compromised database is at risk, potentially affecting a wide range of sensitive business information and user data.

## Recommendation

* Upgrade Budibase Server to a version patched against GHSA-q6x4-v3qx-85qw (greater than 3.38.1) immediately to remediate the `multipleStatements: true` misconfiguration.
* Temporarily disable the MySQL integration within Budibase if immediate patching is not feasible, referencing the 'Remediation' section of the source advisory.
* Implement or strengthen a Web Application Firewall (WAF) to detect and block SQL injection patterns in HTTP request parameters, leveraging webserver log sources.
* Review and restrict the database user privileges for the Budibase application to the absolute minimum necessary functions, limiting the potential impact of future injection vulnerabilities.
