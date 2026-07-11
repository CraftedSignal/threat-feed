---
title: PraisonAI SQL/CQL Injection via Unvalidated PGVector/Cassandra Dimension (CVE-2026-60090)
slug: 2026-07-praisonai-sql-cql-injection
description: PraisonAI versions before 4.6.78 are vulnerable to SQL/CQL injection, allowing an attacker to inject malicious SQL/CQL tokens into generated CREATE TABLE DDL statements by influencing the unvalidated 'dimension' argument in PGVector and Cassandra knowledge-store backends, potentially leading to arbitrary database command execution and data manipulation or destruction.
date: "2026-07-11T14:17:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - cql-injection
  - data-destruction
  - praisonai
  - database-vulnerability
vendors:
  - PraisonAI
products:
  - PraisonAI before 4.6.78
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A caller able to influence collection-creation dimensions can pass a string such as '3); DROP TABLE tenant_secrets; --' to inject SQL/CQL tokens into the statement executed by the database driver.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: A caller able to influence collection-creation dimensions can pass a string such as '3); DROP TABLE tenant_secrets; --' to inject SQL/CQL tokens into the statement executed by the database driver.
    confidence_band: high
cves:
  - id: CVE-2026-60090
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-60090
---

A critical SQL/CQL injection vulnerability, tracked as CVE-2026-60090, affects PraisonAI software versions prior to 4.6.78. The flaw exists within the `create_collection()` function of the PGVector and Cassandra knowledge-store backends, where the `dimension` argument is insufficiently validated. Although other identifiers like schema and collection names undergo validation, the `dimension` value, intended as an integer, is directly interpolated into the vector column of the generated `CREATE TABLE DDL` statement without proper sanitization. An attacker capable of influencing collection-creation dimensions can craft a malicious string, such as `'3); DROP TABLE tenant_secrets; --'`, which, when executed by the database driver, results in the injection of arbitrary SQL/CQL tokens. This can lead to unauthenticated arbitrary command execution within the database, allowing for data manipulation, exfiltration, or destruction. This vulnerability presents a significant risk to the integrity and availability of data managed by PraisonAI deployments.

## Attack Chain

1. An attacker identifies a PraisonAI instance running a vulnerable version (prior to 4.6.78) where they can influence parameters passed to the `create_collection()` function.
2. The attacker crafts a malicious string payload, such as `'3); DROP TABLE tenant_secrets; --'`, designed to inject SQL or CQL commands, and provides this as the `dimension` argument.
3. The PraisonAI application receives the `create_collection()` request but fails to perform adequate validation on the `dimension` argument.
4. PraisonAI interpolates the unvalidated, malicious `dimension` string directly into the dynamic `CREATE TABLE DDL` statement intended for the connected PGVector or Cassandra database.
5. The database driver executes the constructed DDL statement, which now includes the attacker's injected SQL/CQL commands.
6. The database processes and executes the injected command, leading to the intended malicious action, such as dropping the `tenant_secrets` table.

## Impact

Successful exploitation of CVE-2026-60090 grants an attacker the ability to execute arbitrary SQL or CQL commands against the underlying database. This high-severity vulnerability (CVSS v3.1 Base Score: 9.8) can lead to severe consequences, including unauthorized data modification, deletion, or exfiltration. Attackers could drop critical tables, manipulate database schema, or insert malicious data, severely compromising data integrity and availability. Organizations using PraisonAI are at risk of significant data loss, operational disruption, and potential regulatory non-compliance due to uncontrolled database access.

## Recommendation

* Patch CVE-2026-60090 by upgrading PraisonAI to version 4.6.78 or later immediately.
* Implement robust input validation for all user-supplied parameters, especially those interpolated into database queries, to prevent SQL/CQL injection vulnerabilities as described for the `dimension` argument.
* Monitor database logs for unusual DDL statements, such as `DROP TABLE` or `ALTER TABLE`, particularly if originating from the PraisonAI application's database user.
