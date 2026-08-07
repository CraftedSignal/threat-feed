---
title: PostgreSQL COPY PROGRAM Command Execution
slug: 2026-07-postgresql-copy-program
description: The PostgreSQL 'COPY ... PROGRAM' feature enables users with elevated privileges to execute arbitrary operating-system commands, a technique frequently abused by attackers to deploy cryptominers or establish persistence.
date: "2026-07-31T19:10:28Z"
lastmod: "2026-08-07T15:16:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*
tags:
  - postgresql
  - execution
  - network-security
vendors:
  - PostgreSQL
products:
  - PostgreSQL
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Identifies PostgreSQL COPY statements that invoke an operating-system command through the PROGRAM option.
    confidence_band: high
cves:
  - id: CVE-2019-9193
    cvss: 7.2
    epss: 0.91655
references:
  - https://www.postgresql.org/docs/current/sql-copy.html
  - https://www.aquasec.com/blog/pg_mem-a-malware-hidden-in-the-postgres-processes/
  - https://www.wiz.io/blog/postgresql-cryptomining
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/linux_suspicious_child_process_of_postgresql.yml
rules:
  - title: Detect PostgreSQL COPY PROGRAM Command Execution
    description: Detects usage of the PostgreSQL COPY command with the PROGRAM option, which can be abused to execute arbitrary OS commands.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - network_connection
rules_count: 1
updates:
  - at: "2026-08-07T15:16:44Z"
    level: L2
    summary: added CVE-2019-9193
    sources:
      - splunk-escu
    source_urls:
      - https://github.com/splunk/security_content/blob/main/detections/endpoint/linux_suspicious_child_process_of_postgresql.yml
---

The PostgreSQL database management system supports the `COPY ... FROM PROGRAM` and `COPY ... TO PROGRAM` SQL commands, which allow the database to interact directly with the underlying host operating system. While intended for administrative data-processing tasks such as importing or exporting files, this functionality provides an avenue for command execution when accessed by a superuser or a role possessing the `pg_execute_server_program` privilege.

Threat actors who successfully obtain privileged database credentials often exploit this feature to bypass typical application-layer restrictions. By initiating a `COPY` statement containing the `PROGRAM` keyword, attackers can spawn shells (e.g., `bash`, `sh`), execute downloaders (`curl`, `wget`), or run malicious payloads like cryptominers directly within the security context of the PostgreSQL service account. This technique is well-documented in various post-compromise scenarios, including widespread automated cryptomining campaigns that target exposed or weakly protected database instances. Defenders should monitor database query traffic for the presence of the `PROGRAM` keyword within `COPY` statements to detect unauthorized process execution.

## Attack Chain

1. An attacker gains access to the database using compromised or brute-forced superuser credentials.
2. The attacker identifies the database as a target for persistence or resource exploitation (e.g., cryptomining).
3. The attacker issues a `COPY ... FROM PROGRAM` or `COPY ... TO PROGRAM` SQL statement via an active database session.
4. The PostgreSQL process engine parses the `PROGRAM` keyword and invokes the specified command through an OS shell.
5. The OS shell executes the attacker's payload (e.g., a shell script or binary) using the privileges of the `postgres` service account.
6. The payload performs subsequent malicious actions, such as establishing a reverse shell, downloading additional malware, or initiating cryptomining processes.
7. The attacker maintains persistence by leveraging the shell access to install backdoors or scheduled tasks on the underlying host.

## Impact

Successful exploitation allows for arbitrary code execution on the database server, leading to potential data exfiltration, ransomware deployment, or long-term resource hijacking for cryptomining. These campaigns can impact any organization running PostgreSQL where database access controls are insufficient or where the `pg_execute_server_program` privilege is assigned to non-administrative service accounts.

## Recommendation

- Monitor network query logs for any `COPY` SQL statement containing the `PROGRAM` keyword using the provided Sigma rule.
- Audit database roles to ensure that `pg_execute_server_program` privileges are restricted strictly to authorized administrative accounts.
- Implement endpoint process monitoring to detect the PostgreSQL service account spawning unauthorized child processes such as `sh`, `bash`, `curl`, `wget`, or cryptomining binaries.
- Review PostgreSQL audit logs and network traffic for suspicious database activity, including unusual enumeration or unexpected queries following successful authentication.
- Deploy the Sigma rule below to detect potentially malicious `COPY` statements in network telemetry.
