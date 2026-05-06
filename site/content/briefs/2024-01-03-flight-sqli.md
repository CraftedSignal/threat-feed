---
title: Flight Framework SQL Injection Vulnerability
slug: 2024-01-03-flight-sqli
description: Flight framework is vulnerable to SQL Injection; an attacker can inject arbitrary SQL by crafting malicious array keys due to SimplePdo::insert(), SimplePdo::update(), and SimplePdo::delete() building SQL statements by concatenating the $table argument and the keys of the $data array directly into the query, with no identifier quoting or validation, leading to privilege escalation, arbitrary column writes, data destruction, and exfiltration.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - vulnerability
vendors:
  - composer
products:
  - flightphp/core (< 3.18.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-xwqr-rcqg-22mr
rules:
  - title: Detect Flight Framework SQL Injection Attempt via Malicious Array Keys
    description: Detects potential SQL injection attempts in Flight framework applications by monitoring for suspicious patterns in HTTP request bodies, specifically focusing on array keys containing SQL syntax.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Malicious Parameters in Flight Framework SimplePdo::update()
    description: Detects suspicious `SimplePdo::update()` calls in the Flight framework that could indicate SQL injection attempts through the `where` parameter.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Flight framework, specifically versions prior to 3.18.1, contains an SQL injection vulnerability in the `SimplePdo` class. The `insert()`, `update()`, and `delete()` methods construct SQL queries by directly concatenating the `$table` argument and the keys of the `$data` array into the query string without proper sanitization or validation. This allows an attacker to inject arbitrary SQL commands by crafting malicious array keys when user-controlled data is forwarded to these helper methods (e.g., `$db->insert('users', $request->data->getData())`). Discovered by @Rootingg, this vulnerability was addressed in commit b8dd23a and assigned CVE-2026-42550. Exploitation of this flaw can lead to privilege escalation, arbitrary data modification, and complete data exfiltration.

## Attack Chain

1.  Attacker identifies an application endpoint that uses the Flight framework and its database interaction methods (insert, update, delete).
2.  The application uses `SimplePdo::insert()`, `SimplePdo::update()`, or `SimplePdo::delete()` with user-supplied data. For example: `$db->insert('users', $request->data->getData());`
3.  The attacker crafts a malicious JSON payload with SQL injection in the array keys, such as `{"name, is_admin) VALUES (?, 1);-- ": "attacker_injected"}`.
4.  The attacker sends the crafted JSON payload to the vulnerable endpoint via an HTTP POST request.
5.  The application processes the JSON data and passes it to the vulnerable `SimplePdo` method.
6.  The `SimplePdo` method concatenates the malicious array keys directly into the SQL query without validation or escaping. This results in the creation of an injected SQL query such as `INSERT INTO users (name, is_admin) VALUES (?, 1);-- ) VALUES (?)`.
7.  The database executes the injected SQL query, leading to unintended modifications, such as the creation of an administrative account or modification of existing data.
8.  The attacker escalates privileges, exfiltrates data, or causes data destruction depending on the nature of the injected SQL.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to severe consequences, including unauthorized privilege escalation, allowing attackers to gain administrative control over the application. Attackers can also arbitrarily modify database columns, leading to data corruption or manipulation. Furthermore, data destruction and exfiltration are possible through the use of the `$where` parameter, potentially resulting in complete data loss or exposure of sensitive information. This vulnerability affects applications using Flight framework versions prior to 3.18.1.

## Recommendation

*   Upgrade to Flight framework version 3.18.1 or later, which includes the fix for CVE-2026-42550 with the `requireSafeIdentifier()` helper function.
*   Implement input validation and sanitization on all user-supplied data before passing it to database interaction methods, even after upgrading the Flight framework.
*   Deploy the Sigma rule "Detect Flight Framework SQL Injection Attempt via Malicious Array Keys" to identify potential exploitation attempts by monitoring for suspicious patterns in HTTP request bodies and application logs.
*   Review and audit all existing code that uses `SimplePdo::insert()`, `SimplePdo::update()`, and `SimplePdo::delete()` to ensure proper data sanitization and prevent SQL injection vulnerabilities.
