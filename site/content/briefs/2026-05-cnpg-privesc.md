---
title: CloudNativePG Metrics Exporter Privilege Escalation and RCE (CVE-2026-44477)
slug: 2026-05-cnpg-privesc
description: CVE-2026-44477 allows a low-privileged database user to escalate to PostgreSQL superuser and achieve OS command execution as the `postgres` user within the primary pod by exploiting the metrics exporter's superuser connection via custom metric queries or the default configuration.
date: "2026-05-11T16:01:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - remote-code-execution
  - CVE-2026-44477
  - CloudNativePG
vendors:
  - CloudNativePG
products:
  - CloudNativePG < 1.28.3
  - CloudNativePG >= 1.29.0, < 1.29.1
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-423p-g724-fr39
rules:
  - title: Detect CloudNativePG Postgres User Pod RCE
    description: Detects OS command execution via `COPY ... TO PROGRAM` within a PostgreSQL pod, indicating potential exploitation of CVE-2026-44477.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.004
      - T1548.001
    data_sources:
      - process_creation
      - linux
  - title: Detect CloudNativePG Metrics Exporter PrivEsc via Shadowed current_database
    description: Detects the creation of a function named `current_database` in the public schema of a PostgreSQL database, potentially indicating an attempt to exploit CVE-2026-44477 through the metrics exporter.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-44477, exists in the CloudNativePG metrics exporter that allows a low-privileged database user to gain PostgreSQL superuser privileges and execute arbitrary OS commands as the `postgres` user inside the primary pod. This is due to the exporter initially connecting to PostgreSQL as the `postgres` superuser and then demoting privileges using `SET ROLE pg_monitor`, while retaining the superuser identity in the session. This vulnerability affects deployments using custom metric queries with unqualified identifiers and deployments with default monitoring enabled. The attacker can leverage `RESET ROLE` to recover superuser privileges and then use `COPY ... TO PROGRAM` to execute OS-level subprocesses. Multi-tenant platforms that allow customers to influence custom metric queries are at the highest risk. Patches addressing this vulnerability have been released in versions 1.29.1 and 1.28.3 and later.

## Attack Chain

1. An attacker gains access to a low-privileged database role (e.g., the default `app` role).
2. The attacker identifies a target database being scraped by the CloudNativePG metrics exporter.
3. (Path 1: Custom Metric Queries) The attacker plants a shadow object (e.g., function, view) in a schema on the `search_path` of the target database, with the same name as an unqualified identifier used in a custom metric query.
4. (Path 2: Default Monitoring) The attacker plants a shadow object named `current_database()` in a user database, exploiting the unqualified call in the `pg_extensions` metric.
5. When the metrics exporter next scrapes the database, the shadow object's code is executed within the exporter's `session_user = postgres` session.
6. The attacker's code executes `RESET ROLE` to recover superuser privileges within the scrape session.
7. The attacker's code then uses `COPY ... TO PROGRAM` to execute an arbitrary OS command as the `postgres` user inside the primary pod.
8. The attacker achieves arbitrary OS command execution inside the database pod, potentially leading to further lateral movement or data exfiltration.

## Impact

Successful exploitation allows privilege escalation from a low-privileged database role to PostgreSQL superuser, combined with arbitrary OS command execution as the `postgres` user inside the primary pod. A web application SQL injection vulnerability in an app backed by a CloudNativePG cluster is sufficient to pivot to database-pod RCE. All deployments with default monitoring enabled or custom metric queries containing unqualified catalog references are affected. Multi-tenant platforms are at the highest risk.

## Recommendation

*   Upgrade CloudNativePG to v1.28.3 or later, or v1.29.1 or later to incorporate the fixes described in the advisory, specifically addressing CVE-2026-44477.
*   Apply the workaround by schema-qualifying all identifiers in custom metric queries as described in the advisory, using explicit `pg_catalog.` prefixes.
*   Restrict database ownership to fully trusted roles, ensuring only these roles own user databases in scraped clusters to limit the exploit's impact, per the advisory recommendations.
*   Deploy the Sigma rule "Detect CloudNativePG Postgres User Pod RCE" to identify potential exploitation attempts leveraging the COPY command to program, based on process creation logs.
*   Deploy the Sigma rule "Detect CloudNativePG Metrics Exporter PrivEsc via Shadowed current_database" to detect the shadowing of current_database function.
