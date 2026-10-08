---
title: SQL Injection in MariaDB Connector/Node.js
slug: 2026-10-mariadb-node-sqli
description: The MariaDB Connector/Node.js fails to properly escape input parameters for the text protocol when NO_BACKSLASH_ESCAPES mode is enabled, allowing attackers to perform SQL injection via standard placeholder APIs.
date: "2026-10-08T19:43:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mariadb:mariadb_connector_nodejs:*:*:*:*:*:node.js:*:*
vendors:
  - MariaDB
products:
  - MariaDB Connector/Node.js (< 3.2.5, >= 3.3.0 < 3.3.4, >= 3.4.0 < 3.4.7, >= 3.5.0-rc.0 < 3.5.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker able to influence any value the application passes as a query parameter could execute arbitrary SQL.
    confidence_band: high
cves:
  - id: CVE-2026-107385
    cvss: 7.4
references:
  - https://github.com/advisories/GHSA-r3rv-jm3r-62q2
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-107385
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade MariaDB Connector/Node.js to 3.2.5 or later
      owner: IT Operations
      due: 72h
      evidence: Source provides list of vulnerable versions and resolution
  mitigation_plan:
    - priority: immediate
      action: Switch database query methods to use execute() or batch() instead of query()
      owner: Application Security
      addresses: CVE-2026-107385
      evidence: Source states execute() and batch() are not affected
---

MariaDB Connector/Node.js (CVE-2026-107385) contains a vulnerability in its parameter-escaping logic for the text protocol. When a database session is configured with the NO_BACKSLASH_ESCAPES SQL mode, the connector fails to recognize the mode, continuing to escape quotes with backslashes rather than doubling them. This behavior results in a mismatch where the escaped value prematurely closes the SQL string literal. An attacker capable of influencing query parameters can escape the string context and inject arbitrary SQL commands. The vulnerability affects all standard text-protocol entry points, including the Connection.escape() method. While the vulnerability requires the specific NO_BACKSLASH_ESCAPES mode to be active, this can be set server-wide, via connector session initialization, or through individual application queries. The binary prepared-statement protocol (execute/batch) remains unaffected.

## Attack Chain

1. Attacker identifies a web application using the vulnerable MariaDB Connector/Node.js driver.
2. Attacker verifies the target database session has the NO_BACKSLASH_ESCAPES SQL mode enabled.
3. Attacker identifies an application input field that passes data to a SQL query using the connector's text protocol (e.g., query() method).
4. Attacker submits a crafted payload containing a single quote, which the connector improperly escapes with a backslash.
5. The backslash, treated as a literal character in NO_BACKSLASH_ESCAPES mode, fails to prevent the quote from terminating the string literal.
6. The injected SQL following the terminated string literal is parsed and executed by the MariaDB server.
7. Attacker achieves unauthorized data exfiltration, modification, or deletion based on the application's database user permissions.

## Impact

Successful exploitation allows for unauthenticated or authenticated SQL injection, leading to unauthorized read, modification, or deletion of database contents. The impact is equivalent to the privileges granted to the database user account used by the application, which may expose sensitive organizational data or compromise application integrity.

## Recommendation

Prioritize upgrading the MariaDB Connector/Node.js package to a version that addresses CVE-2026-107385 (>= 3.2.5, >= 3.3.4, >= 3.4.7, or >= 3.5.4). If immediate patching is not possible, enforce the use of the binary protocol (execute() or batch()) for all database interactions, as these methods are not affected by this flaw. Audit application-level configurations to determine if NO_BACKSLASH_ESCAPES mode is explicitly enabled within session variables or initialization scripts.
