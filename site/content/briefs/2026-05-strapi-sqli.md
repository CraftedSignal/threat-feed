---
title: Strapi Content-Type Builder SQL Injection Vulnerability (CVE-2026-22599)
slug: 2026-05-strapi-sqli
description: A SQL injection vulnerability, identified as CVE-2026-22599, affects Strapi's Content-Type Builder, where an authenticated administrator could inject arbitrary database statements through the `column.defaultTo` attribute, potentially leading to arbitrary file read, denial of service, or remote code execution on the database server.
date: "2026-05-13T20:05:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - vulnerability
  - strapi
vendors:
  - Strapi
products:
  - '@strapi/content-type-builder'
  - '@strapi/plugin-content-type-builder'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
references:
  - https://github.com/advisories/GHSA-3xcq-8mjw-h6mx
  - CVE-2026-22599
rules:
  - title: Detect CVE-2026-22599 Exploitation Attempt - Content-Type Builder Access
    description: Detects CVE-2026-22599 exploitation attempt - HTTP POST or PUT request to Content-Type Builder endpoints
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
  - title: Detect CVE-2026-22599 Exploitation Attempt - Content-Type Builder Access in Production
    description: Detects CVE-2026-22599 exploitation attempt in production environments - HTTP POST or PUT request to Content-Type Builder endpoints, which should be disabled.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-22599 is a critical SQL injection vulnerability affecting the Strapi Content-Type Builder, specifically versions <=5.33.1 of `@strapi/content-type-builder` (v5) and <=4.26.0 of `@strapi/plugin-content-type-builder` (v4). This vulnerability allows an authenticated administrator to inject arbitrary database statements through the `column.defaultTo` attribute during content type creation or modification. By setting `defaultTo` as a tuple `[value, { isRaw: true }]`, the provided value is directly passed to Knex's `db.connection.raw()` without proper sanitization, leading to arbitrary statement execution at the database layer. Successful exploitation could result in arbitrary file read, denial of service via server crash, and, depending on the database engine, remote code execution on the database server. The vulnerability can be remediated by updating Strapi to versions >=5.33.2 (v5) or >=4.26.1 (v4), which restricts Content-Type Builder write APIs to development mode only.

## Attack Chain

1. An attacker authenticates as an administrator in Strapi.
2. The attacker crafts a malicious HTTP POST or PUT request to `/content-type-builder/content-types` or related endpoints.
3. The request includes a payload designed to create or modify a content type.
4. Within the payload, the `column.defaultTo` attribute is set with a tuple `[value, { isRaw: true }]`. The `value` contains a SQL injection payload.
5. Strapi's Content-Type Builder processes the request and passes the `value` directly into Knex's `db.connection.raw()` function.
6. The database executes the injected SQL statement, performing actions such as arbitrary file read, causing a denial-of-service by crashing the server, or potentially executing arbitrary code on the database server, depending on the database engine's capabilities.
7. The attacker exfiltrates sensitive data read from the file system.
8. The attacker gains unauthorized access to the Strapi application or the database server.

## Impact

Successful exploitation of CVE-2026-22599 can lead to severe consequences, including unauthorized access to sensitive data, denial of service, and potentially remote code execution on the database server. Observed damage includes unexpected files appearing on the database host, Strapi server crashes following content-type creation or updates, and unusual DEFAULT clause values in database server logs. The vulnerability affects any Strapi instance running vulnerable versions of the `@strapi/content-type-builder` or `@strapi/plugin-content-type-builder` packages.

## Recommendation

*   Immediately update Strapi to versions >=5.33.2 (v5) or >=4.26.1 (v4) to apply the patch that restricts Content-Type Builder write APIs to development mode, mitigating the vulnerability described in CVE-2026-22599.
*   Monitor HTTP access logs for POST or PUT requests to `/content-type-builder/content-types` endpoints from non-internal sources using the regex pattern `(POST|PUT)\s+/content-type-builder/` to identify potential exploitation attempts.
*   Analyze database server logs for unexpected DEFAULT clause values that reference filesystem-access or program-execution helper functions to detect successful SQL injection.
*   Deploy the provided Sigma rule to detect potential exploitation attempts based on HTTP requests to the Content-Type Builder endpoints.
