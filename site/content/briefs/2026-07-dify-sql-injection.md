---
title: Dify MyScale Backend SQL Injection Vulnerability (CVE-2026-61461)
slug: 2026-07-dify-sql-injection
description: A high-severity SQL injection vulnerability, CVE-2026-61461, exists in the MyScale vector store backend of Dify versions prior to 1.16.0-rc1, allowing attackers with low privileges to execute arbitrary SQL commands via unsanitized search parameters, leading to unauthorized data manipulation in the underlying ClickHouse database.
date: "2026-07-10T19:23:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-vulnerability
  - dify
  - clickhouse
vendors:
  - langgenius
products:
  - Dify
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: allows attackers to execute arbitrary SQL by supplying unsanitized search parameters
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: ""
    evidence: Attackers can inject malicious SQL through the search parameters to read, modify, or delete data in the underlying ClickHouse database.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Attackers can inject malicious SQL through the search parameters to read, modify, or delete data in the underlying ClickHouse database.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Attackers can inject malicious SQL through the search parameters to read, modify, or delete data in the underlying ClickHouse database.
    confidence_band: high
cves:
  - id: CVE-2026-61461
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61461
  - https://github.com/langgenius/dify/commit/d9884efaeea8322706e24c560d2c17e5bf3fab5f
  - https://github.com/langgenius/dify/issues/38281
  - https://github.com/langgenius/dify/pull/38295
  - https://github.com/langgenius/dify/releases/tag/1.16.0-rc1
  - https://www.vulncheck.com/advisories/dify-rc1-sql-injection-via-myscale-vector-store-search-by-full-text
rules:
  - title: Detect CVE-2026-61461 Exploitation - Dify MyScale SQL Injection
    description: Detects CVE-2026-61461 exploitation - attempts to inject SQL commands into Dify's MyScale vector store backend via the search_by_full_text method by looking for common SQL injection patterns in URL query parameters. This targets endpoints typically used for search functionality.
    platform: sigma
    severity: high
    tactics:
      - collection
      - execution
      - impact
    techniques:
      - T1005
      - T1059.006
      - T1485
      - T1565.002
    data_sources:
      - webserver
rules_count: 1
---

Dify, an open-source LLM application development platform, is affected by CVE-2026-61461, a high-severity SQL injection vulnerability discovered in versions prior to 1.16.0-rc1. This flaw resides in the MyScale vector store backend, specifically within the `search_by_full_text` method. The vulnerability arises because search parameters supplied to this method are not properly sanitized or parameterized, allowing an attacker with low privileges (CVSS:PR:L) to inject arbitrary SQL code. Successful exploitation can lead to unauthorized reading, modification, or deletion of sensitive data stored in the underlying ClickHouse database, posing a significant risk to data integrity and confidentiality within affected Dify deployments.

## Attack Chain

1. An attacker identifies a Dify instance running a vulnerable version (prior to 1.16.0-rc1) configured to use the MyScale vector store backend.
2. The attacker gains low-privileged access to the Dify application, as indicated by the CVSS 'PR:L' metric.
3. The attacker crafts a malicious HTTP request targeting a Dify endpoint that utilizes the `search_by_full_text` method in the MyScale backend.
4. The request includes unsanitized search parameters containing SQL injection payloads, such as special characters, keywords like `UNION SELECT`, or comments.
5. The vulnerable `search_by_full_text` method processes these parameters directly, without proper escaping or prepared statements.
6. The injected SQL commands are then executed by the underlying ClickHouse database.
7. The attacker achieves unauthorized data access, modification, or deletion within the ClickHouse database, impacting confidentiality, integrity, or availability.

## Impact

Successful exploitation of CVE-2026-61461 can lead to severe consequences for organizations using affected Dify versions. Attackers can gain comprehensive control over the underlying ClickHouse database, enabling them to exfiltrate sensitive user data, application configurations, or proprietary information. Furthermore, they can modify or delete critical data, which could lead to severe data integrity issues, service disruption, and potential legal or compliance penalties. The high CVSS score of 8.8 reflects the significant potential for impact on confidentiality, integrity, and availability.

## Recommendation

* Patch CVE-2026-61461 by upgrading Dify to version 1.16.0-rc1 or newer immediately, as referenced in the provided GitHub releases.
* Deploy the Sigma rule "Detect CVE-2026-61461 Exploitation - Dify MyScale SQL Injection" from this brief to your SIEM to detect attempts at SQL injection targeting Dify's `search_by_full_text` method.
* Monitor web server access logs for unusual request patterns, specifically looking for SQL injection keywords and special characters in `cs-uri-query` parameters, as indicated by the log source `webserver`.
