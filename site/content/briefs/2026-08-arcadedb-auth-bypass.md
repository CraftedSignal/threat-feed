---
title: Authorization Bypass in ArcadeDB SQL DEFINE FUNCTION
slug: 2026-08-arcadedb-auth-bypass
description: ArcadeDB versions before 26.7.2 contain an authorization bypass vulnerability (CVE-2026-67341) that permits unprivileged users to execute arbitrary JavaScript code via the DEFINE FUNCTION statement.
date: "2026-08-01T13:51:18Z"
lastmod: "2026-08-01T13:51:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authorization-bypass
  - cve-2026-67342
vendors:
  - ArcadeData
products:
  - ArcadeDB
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers with database access can execute arbitrary JavaScript code by submitting DEFINE FUNCTION statements, bypassing security controls intended to restrict scripting to administrators.
    confidence_band: high
cves:
  - id: CVE-2026-67341
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67341
  - https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-vwjc-v7x7-cm6g
  - https://www.vulncheck.com/advisories/arcadedb-before-authorization-bypass-via-sql-define-function
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67342
  - https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-x8mg-6r4p-87pf
rules:
  - title: Detect CVE-2026-67342 Exploitation - ArcadeDB Unauthorized API Access
    description: Detects potential exploitation of CVE-2026-67342 by monitoring for unauthorized access attempts to sensitive ArcadeDB endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-08-01T13:51:26Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-67342 Exploitation - ArcadeDB Unauthorized API Access'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-67342
---

ArcadeDB versions prior to 26.7.2 are vulnerable to an authorization bypass flaw, tracked as CVE-2026-67341. The vulnerability exists within the SQL engine's handling of the `DEFINE FUNCTION` command when the `LANGUAGE` parameter is set to `js`. The application fails to properly enforce security checks that should restrict the registration of functions to administrative users. An attacker with database access can leverage this defect to register and execute arbitrary JavaScript code. This vulnerability has a critical impact, potentially allowing for full system compromise or unauthorized access to sensitive database data, as the code executes within the context of the database process.

## Attack Chain

1. Attacker establishes a connection to the target ArcadeDB instance.
2. Attacker crafts a malicious SQL `DEFINE FUNCTION` statement specifying `LANGUAGE js`.
3. Attacker embeds arbitrary JavaScript payload into the function body.
4. Attacker executes the SQL statement against the target database.
5. The ArcadeDB engine fails to validate the user's authorization level for the `DEFINE FUNCTION` operation.
6. The database engine registers the malicious function.
7. Attacker invokes the newly created function to execute the malicious JavaScript payload.
8. Attacker achieves command execution within the database engine context.

## Impact

Successful exploitation of this vulnerability allows unauthorized users to achieve arbitrary code execution within the database engine. This can lead to full compromise of the database integrity, confidentiality, and availability, depending on the permissions of the database process. The vulnerability affects all ArcadeDB deployments running versions prior to 26.7.2.

## Recommendation

* Upgrade all ArcadeDB instances to version 26.7.2 or later immediately to address the authorization check failure.
* Audit database logs for the usage of the `DEFINE FUNCTION` command, specifically looking for JavaScript-based functions created by non-administrative service accounts.
* Restrict network access to the ArcadeDB management ports to prevent unauthorized actors from reaching the database interface.
* Monitor database activity for unexpected execution of custom functions.
