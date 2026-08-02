---
title: SQL Injection in PyAthena DefaultParameterFormatter
slug: 2026-08-pyathena-sql-injection
description: Unauthenticated attackers can achieve arbitrary SQL execution in PyAthena versions prior to 3.35.4 by exploiting improper quote-escaping within the DefaultParameterFormatter.format() function.
date: "2026-08-02T15:36:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
products:
  - PyAthena (< 3.35.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows unauthenticated attackers to inject arbitrary SQL.
    confidence_band: high
cves:
  - id: CVE-2026-65321
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65321
---

PyAthena versions prior to 3.35.4 contain a critical SQL injection vulnerability originating from the DefaultParameterFormatter.format() method. The issue resides in the _escape_hive function, which incorrectly attempts to escape single quotes using backslashes. Because the underlying Athena and Trino SQL engines do not recognize backslashes as valid escape characters for string literals, the use of a single quote in user-supplied input allows an attacker to prematurely terminate a string literal. This flaw enables the injection of arbitrary SQL commands, potentially leading to unauthorized data exfiltration via UNION SELECT queries, execution of destructive administrative commands, or modification of CTAS (Create Table As Select) operations to point to attacker-controlled destinations. This vulnerability impacts all applications utilizing PyAthena as a connector for Athena or Trino.

## Impact

Successful exploitation allows unauthenticated attackers to bypass application-level input validation to interact directly with the database. Consequences include the loss of sensitive data via unauthorized queries, database modification or deletion, and potential privilege escalation within the context of the database service. The scope includes any environment utilizing PyAthena versions earlier than 3.35.4.

## Recommendation

1. Upgrade the PyAthena library to version 3.35.4 or later immediately to patch the vulnerable DefaultParameterFormatter.format() implementation.
2. Implement strict input validation at the application layer to sanitize all parameters passed to PyAthena, rejecting inputs containing single quotes, semicolons, or SQL comment syntax.
3. Enforce the principle of least privilege for the database credentials used by the application, ensuring the service user lacks permissions to execute destructive commands (e.g., DROP, DELETE) or access unauthorized tables.
4. Review application code for direct concatenation of user-supplied variables into SQL queries, transitioning instead to parameterized queries wherever supported by the underlying connector logic.
