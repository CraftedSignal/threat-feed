---
title: Marten Full-Text Search SQL Injection Vulnerability (CVE-2026-45288)
slug: 2026-05-marten-sql-injection
description: Marten versions up to 8.36 are vulnerable to SQL injection due to the `regConfig` parameter in full-text search APIs not being properly validated or parameterized, allowing attackers to inject arbitrary SQL commands by manipulating the `regConfig` parameter, potentially leading to information disclosure, data manipulation, or denial-of-service; version 8.36.1 addresses this vulnerability.
date: "2026-05-14T20:47:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - cve
  - ghsa
  - web-application
vendors:
  - JasperFx
products:
  - Marten (<= 8.36)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-vmw2-qwm8-x84c
  - https://github.com/JasperFx/marten/pull/4343
  - https://cwe.mitre.org/data/definitions/89.html
  - https://github.com/JasperFx/marten/blob/master/src/Marten/Linq/SqlGeneration/Filters/FullTextWhereFragment.cs
  - https://github.com/JasperFx/marten/blob/master/src/LinqTests/Bugs/full_text_regconfig_sql_injection.cs
rules:
  - title: Detects CVE-2026-45288 Exploitation — Marten SQL Injection via regConfig
    description: Detects CVE-2026-45288 exploitation — SQL injection attempts in HTTP requests targeting Marten applications by looking for shell metacharacters or SQL keywords in the regConfig parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-45288 Exploitation — Marten regConfig Validation Bypass Attempt
    description: Detects CVE-2026-45288 exploitation — detects attempts to bypass the intended regConfig validation by using schema-qualified names with injection attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Marten, a .NET transactional document database and event store, contains a SQL injection vulnerability (CVE-2026-45288) in versions 8.36 and earlier. The vulnerability stems from the improper handling of the `regConfig` parameter within its full-text search APIs. Specifically, the `regConfig` parameter, intended to specify the text search configuration, is directly interpolated into SQL queries without sufficient validation or parameterization. This allows an attacker to inject arbitrary SQL commands by crafting a malicious `regConfig` value. Successful exploitation can lead to unauthorized data access, modification, or denial-of-service. The vulnerability was privately reported and patched in version 8.36.1 by introducing regular expression validation of the `regConfig` parameter.

## Attack Chain

1. The attacker identifies an application using a vulnerable version of Marten (<= 8.36) with exposed `regConfig` parameter.
2. The attacker crafts a malicious `regConfig` value containing SQL injection payloads (e.g., `english'; SELECT version(); --`).
3. The attacker injects the malicious `regConfig` value into one of the vulnerable API endpoints like `IQuerySession.SearchAsync<T>(string searchTerm, string regConfig, ...)` via a request parameter (e.g. `?lang=`).
4. The Marten application receives the request and incorporates the malicious `regConfig` value into the generated SQL query.
5. The database executes the attacker-injected SQL commands. This could involve selecting data, dropping tables, or causing delays using `pg_sleep`.
6. The attacker observes the effects of the injected SQL, such as information disclosure through error messages or timing differences, or direct extraction if query results are surfaced.
7. The attacker escalates the attack based on the initial success, potentially gaining full control over the database contents or disrupting service availability.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-45288) can have severe consequences. An attacker could gain unauthorized access to sensitive data, leading to confidentiality breaches. Data integrity is also at risk, as attackers can modify or delete data. Furthermore, attackers can cause denial-of-service by injecting commands that consume excessive resources or disrupt database operations. The specific impact depends on the privileges of the database user used by the Marten application.

## Recommendation

*   Upgrade Marten to version 8.36.1 or later to remediate the vulnerability. The patch introduces validation on the `regConfig` parameter ([JasperFx/marten#4343](https://github.com/JasperFx/marten/pull/4343)).
*   If upgrading is not immediately feasible, implement one of the suggested workarounds, such as hardcoding `regConfig` or validating user-supplied input against a safe regex.
*   Monitor web server logs for requests containing potentially malicious SQL injection attempts in the `regConfig` parameter. Deploy the Sigma rule to detect SQL injection attempts in HTTP requests targeting Marten applications.
*   Implement input validation on the application layer to sanitize user input before passing it to Marten, specifically for the `regConfig` parameter.
