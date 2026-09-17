---
title: SQL Injection in Marten LINQ Provider via Unescaped Literals
slug: 2026-09-marten-sql-injection
description: Marten versions 7.0.0 through 9.12.0 contain critical SQL injection vulnerabilities in the LINQ provider and tenant-management internals, allowing attackers to perform unauthorized data access, multi-tenant bypass, and data modification via crafted dictionary keys or tenant IDs.
date: "2026-09-17T19:10:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:marten:marten:7.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:marten:marten:9.12.0:*:*:*:*:*:*:*
tags:
  - marten
  - sql-injection
  - cve-2026-75513
  - dotnet
  - database-security
vendors:
  - Marten
products:
  - Marten (7.0.0 - 9.12.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Several code paths in Marten's LINQ provider and tenant-management internals interpolated a runtime, potentially attacker-influenced value into generated SQL as a single-quoted string literal.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Where the application permits ;-batched statements (Npgsql default), data modification is also possible.
    confidence_band: high
cves:
  - id: CVE-2026-75513
    cvss: 9.1
references:
  - https://github.com/advisories/GHSA-rfx3-98h7-v3xp
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75513
action_plan:
  priority: immediate_escalation
  owners:
    - Application Security
    - IT Operations
  immediate_actions:
    - action: Upgrade Marten library to the latest version beyond 9.12.0.
      owner: IT Operations
      due: 24h
      evidence: Source states Marten 7.0.0 through 9.12.0 are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Disable multi-statement batching in Npgsql connection strings.
      owner: Application Security
      addresses: CVE-2026-75513
      evidence: Source identifies this as a workaround to limit blast radius.
---

Marten, a document database library for .NET using PostgreSQL, contains multiple SQL injection vulnerabilities (CVE-2026-75513) stemming from improper handling of runtime-influenced string inputs. The LINQ provider and tenant management internal components interpolate unsanitized strings directly into SQL queries as single-quoted literals. An attacker can break out of these literals by supplying input containing single quotes, leading to arbitrary SQL execution.

The primary attack vector involves supplying malicious dictionary keys within LINQ `Where` filters (e.g., `x.Attributes[key] == v`), enabling filter bypass and unauthorized cross-tenant data access. Additional vulnerable sinks include `Dictionary.ContainsKey` calls, projection selectors, tenant ID parameters in projection teardown, and DDL generation for database-scoped tenant partitions. If the application environment allows `;` delimited multi-statement queries, which is the default behavior of the underlying Npgsql driver, this vulnerability can facilitate data modification or destruction. Defenders should prioritize upgrading to patched versions immediately and audit code paths that pass user-supplied input to dictionary indexers or tenant-related functions.

## Attack Chain

1. Attacker identifies an application endpoint that uses user-supplied input as a key in a Marten `Dictionary<,>` indexer within a LINQ `Where` filter.
2. Attacker crafts a payload containing a single quote character designed to terminate the SQL string literal and append malicious SQL logic.
3. The Marten LINQ provider receives the payload and interpolates the string into the generated SQL query without parameterization or escaping.
4. The query is transmitted to the PostgreSQL database, where the injected SQL fragment executes with the privileges of the application's database user.
5. The injection modifies the query logic, such as appending `or 1=1 --`, effectively bypassing intended filter conditions or tenant isolation boundaries.
6. The database returns unauthorized records from other tenants or reveals sensitive data through blind SQL injection techniques.
7. If multi-statement support is enabled, the attacker injects a second statement (e.g., `'; DROP TABLE... --`) to perform data modification or destructive actions.

## Impact

Successful exploitation leads to a total compromise of data confidentiality within the affected PostgreSQL database. Attackers can bypass multi-tenancy controls to access data across different partitions, perform blind exfiltration of sensitive information, or potentially execute data modification/deletion attacks. The vulnerability affects a wide range of Marten versions (v7.0.0 through v9.12.0), posing a critical risk to any application relying on these library functions for dynamic filtering or multi-tenant management.

## Recommendation

1. Upgrade Marten to a patched version immediately.
2. If an immediate upgrade is not possible, identify and sanitize all instances where user-controlled input is passed as a key to dictionary indexers (`Where` filters) or arguments to `Dictionary.ContainsKey`.
3. Restrict the use of user-supplied input in `Select` projection constants or tenant ID arguments within projection teardown functions.
4. Disable support for multi-statement command batching in the Npgsql connection string to limit the impact of potential SQL injection payloads.
5. Implement strict input validation and allow-listing for any string intended to be used as a dictionary key or tenant identifier in the data access layer.
