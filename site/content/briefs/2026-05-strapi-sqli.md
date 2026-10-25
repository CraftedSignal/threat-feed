---
brief_id: brief-2026-05-strapi-sqli
event_id: brief-2026-05-strapi-sqli
revision: 2
activity_at: "2026-10-25T05:41:18Z"
revision_history:
  - revision: 2
    at: "2026-10-25T05:41:18Z"
    checksum: sha256:b27185dae902a4fef07d75be8ae1ee92d56d726f3caae0116b7339c0d6d0501f
    summary: poc_available; added CVE-2026-22599; @strapi/plugin-content-type-builder version < 4.26.1; @strapi/content-type-builder version < 4.26.1
    changed_fields:
      - affected_products
      - cpes
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ABRAXAS-CVE-2026-22599&utm_source=rss&utm_medium=rss
title: Strapi Content-Type Builder SQL Injection Vulnerability (CVE-2026-22599)
slug: 2026-05-strapi-sqli
description: A SQL injection vulnerability, identified as CVE-2026-22599, affects Strapi's Content-Type Builder, where an authenticated administrator could inject arbitrary database statements through the `column.defaultTo` attribute, potentially leading to arbitrary file read, denial of service, or remote code execution on the database server.
date: "2026-05-13T20:05:52Z"
lastmod: "2026-10-25T05:40:38Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:strapi:strapi:*:*:*:*:*:node.js:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ABRAXAS-CVE-2026-22599&utm_source=rss&utm_medium=rss
tags:
  - sql-injection
  - vulnerability
  - strapi
vendors:
  - Strapi
products:
  - '@strapi/content-type-builder (< 4.26.1)'
  - '@strapi/plugin-content-type-builder (< 4.26.1)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
cves:
  - id: CVE-2026-22599
    cvss: 7.2
    epss: 0.01178
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-3xcq-8mjw-h6mx
  - CVE-2026-22599
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ABRAXAS-CVE-2026-22599&utm_source=rss&utm_medium=rss
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
updates:
  - at: "2026-10-25T05:40:38Z"
    level: L2
    summary: poc_available; added CVE-2026-22599; @strapi/plugin-content-type-builder version < 4.26.1; @strapi/content-type-builder version < 4.26.1
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ABRAXAS-CVE-2026-22599&utm_source=rss&utm_medium=rss
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
