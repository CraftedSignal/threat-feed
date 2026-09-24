---
title: SQL Injection in ReactPress API via Unsanitized Query Parameter Names
slug: 2026-09-reactpress-sqli
description: An unauthenticated SQL injection vulnerability in ReactPress allows attackers to exfiltrate database contents via malicious HTTP query parameter keys in API requests.
date: "2026-09-24T01:57:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:fecommunity:reactpress:*:*:*:*:*:*:*:*
tags:
  - sqli
  - vulnerability
  - api-security
vendors:
  - fecommunity
products:
  - reactpress (<= 3.6.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can perform blind SQL injection against the application database.
    confidence_band: high
cves:
  - id: CVE-2026-61685
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-wmw4-mw6x-6vfm
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61685
rules:
  - title: Detects CVE-2026-61685 Exploitation - SQL Injection via Query Parameter Keys
    description: Detects exploitation attempts by identifying SQL-specific characters in URL query parameter keys targeting ReactPress API endpoints
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Upgrade @fecommunity/reactpress to >= 3.7.0
      owner: IT Operations
      due: 24h
      evidence: Remediation note in GHSA advisory
  hunt_leads:
    - lead: Search logs for unusual query parameter keys in GET /api/* requests
      technique_id: T1190
      data_needed:
        - webserver logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows injection via HTTP query parameter names
  mitigation_plan:
    - priority: immediate
      action: Block or inspect requests targeting vulnerable endpoints with suspicious query strings
      owner: SOC
      addresses: CVE-2026-61685
      evidence: Summary note regarding GET request endpoints
---

ReactPress versions 3.6.0 and earlier contain a critical SQL injection vulnerability (CVE-2026-61685) due to improper handling of dynamic column names within its API. The application uses unsanitized HTTP query parameter names directly in TypeORM QueryBuilder conditions, specifically constructing identifiers like `article.${key}`. While TypeORM parameterizes values, it does not parameterize column identifiers, allowing an attacker to inject SQL syntax through crafted query keys. This vulnerability affects multiple endpoints including /api/article, /api/comment, /api/file, /api/page, and /api/Knowledge. Successful exploitation allows an unauthenticated remote attacker to perform blind SQL injection, leading to the unauthorized exfiltration of sensitive data such as user credentials, system settings, and proprietary content.

## Attack Chain

1. Attacker identifies a ReactPress instance exposed to the internet.
2. Attacker inspects the API structure and identifies susceptible GET endpoints (/api/article, /api/comment, /api/file, /api/page, /api/Knowledge).
3. Attacker crafts an HTTP GET request containing malicious SQL fragments within a query parameter key (e.g., `?some_col=value` is replaced with `?1=1;--=value`).
4. The ReactPress server parses the query parameter key and dynamically constructs a TypeORM QueryBuilder statement using the malicious key as a column identifier.
5. The resulting unsanitized query is sent to the underlying database driver.
6. The database executes the injected SQL commands alongside legitimate queries.
7. Attacker uses boolean-based or time-based blind SQL injection techniques to extract data character by character based on the server response or latency.

## Impact

Successful exploitation results in unauthorized access to the application database. An attacker can exfiltrate sensitive information, including user records, system configurations, API keys, and article contents. The vulnerability is highly impactful due to its unauthenticated nature, allowing complete compromise of the database layer.

## Recommendation

* Upgrade to `@fecommunity/reactpress` version 3.7.0 or higher immediately to patch CVE-2026-61685.
* If upgrading is not immediately possible, implement a WAF or API gateway rule to inspect and reject incoming HTTP GET requests that contain suspicious SQL syntax or illegal characters within query parameter keys.
* Implement strict allow-listing for all query parameters accepted by the API endpoints listed in this brief.
