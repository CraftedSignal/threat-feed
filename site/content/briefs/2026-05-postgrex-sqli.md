---
title: Postgrex SQL Injection Vulnerability in Notifications.listen/3 (CVE-2026-32687)
slug: 2026-05-postgrex-sqli
description: A SQL injection vulnerability exists in Postgrex versions 0.16.0 to before 0.22.2 within the `Postgrex.Notifications.listen/3` function allowing attackers to execute arbitrary SQL commands on the notifications connection by manipulating the channel name.
date: "2026-05-18T17:53:57Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - sql-injection
  - vulnerability
  - postgrex
vendors:
  - erlang
products:
  - postgrex
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-32687
    epss: 0.00017
references:
  - https://github.com/advisories/GHSA-r73h-97w8-m54h
rules:
  - title: Detect CVE-2026-32687 Exploitation — Malicious Channel Name in Postgrex Notifications
    description: Detects CVE-2026-32687 exploitation — Attempts to inject SQL commands via the channel name in Postgrex notifications by detecting quote characters in the channel argument.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - application
      - erlang
  - title: Detect CVE-2026-32687 Exploitation — SQL Injection Payloads in Postgrex Notifications
    description: Detects CVE-2026-32687 exploitation — Attempts to inject SQL commands via the channel name in Postgrex notifications by detecting SQL keywords
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - application
      - erlang
rules_count: 2
---

A SQL injection vulnerability has been identified in the Postgrex library, specifically affecting versions 0.16.0 up to 0.22.2. The vulnerability resides in the `Postgrex.Notifications.listen/3` function. The `channel` argument is directly interpolated into the `LISTEN` and `UNLISTEN` SQL commands without proper sanitization, creating an opportunity for attackers to inject arbitrary SQL. This issue could be exploited by any caller who uses a user-influenced channel name without input validation. Successful exploitation could lead to unauthorized data access, modification, or even destruction within the PostgreSQL database. The vulnerability is identified as CVE-2026-32687.

## Attack Chain

1. An attacker crafts a malicious channel name containing SQL injection payloads.
2. The application calls `Postgrex.Notifications.listen/3` or `Postgrex.Notifications.unlisten/3` with the malicious channel name.
3. Postgrex interpolates the unsanitized channel name into a `LISTEN` or `UNLISTEN` SQL command.
4. The injected SQL command is executed on the notifications connection.
5. The attacker can execute arbitrary SQL commands, such as creating tables, dropping tables, or creating roles.
6. This can lead to privilege escalation within the database.
7. Sensitive data can be accessed, modified, or deleted.
8. The attacker gains control over the application's database.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-32687) can allow attackers to execute arbitrary SQL commands on the database, potentially leading to unauthorized data access, modification, or destruction. Since the notifications connection runs as the application's database role, the attacker can read, modify, or destroy any data that the application's DB role has access to. This could have a severe impact on the application's functionality and data integrity.

## Recommendation

- Upgrade to Postgrex version 0.22.2 or later to patch the vulnerability.
- Sanitize user input used as channel names in `Postgrex.Notifications.listen/3` and `Postgrex.Notifications.unlisten/3` by ensuring it does not contain quotes or null bytes, as recommended in the advisory.
- Deploy the Sigma rules provided below to detect potential exploitation attempts in your environment.
