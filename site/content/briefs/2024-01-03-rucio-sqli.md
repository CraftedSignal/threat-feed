---
title: Rucio SQL Injection Vulnerability in FilterEngine PostgreSQL Query Builder
slug: 2024-01-03-rucio-sqli
description: A SQL injection vulnerability exists in Rucio's FilterEngine.create_postgres_query, affecting versions 1.30.0 to before 35.8.5, 36.0.0 to before 38.5.5, 39.0.0 to before 39.4.2, and 40.0.0 to before 40.1.1, allowing any authenticated Rucio user to execute arbitrary SQL against the PostgreSQL metadata database via the DID search endpoint when the postgres_meta plugin is enabled, potentially leading to data modification, remote code execution, and credential theft.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - cve-2026-29090
  - rucio
vendors:
  - Rucio
products:
  - rucio
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-6j7p-qjhg-9947
rules:
  - title: Detect Suspicious Rucio DID Search Queries
    description: Detects suspicious requests to the Rucio DID search endpoint that may indicate SQL injection attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Rucio Postgres Meta Plugin Enabled
    description: Detects potential exploitation if the postgres_meta plugin is enabled in Rucio.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A SQL injection vulnerability has been identified in Rucio, a scientific data management framework, specifically within the `FilterEngine.create_postgres_query` function. This flaw allows any authenticated Rucio user to inject arbitrary SQL commands into the PostgreSQL metadata database if the `postgres_meta` external metadata plugin is configured. The vulnerability is located in the DID search endpoint (`GET /dids/<scope>/dids/search`). The vulnerable code interpolates attacker-controlled filter keys and values directly into raw SQL statements via Python `str.format`, without proper sanitization. This issue affects Rucio versions 1.30.0 to before 35.8.5, 36.0.0 to before 38.5.5, 39.0.0 to before 39.4.2, and 40.0.0 to before 40.1.1. Exploitation can lead to full database compromise, including sensitive data exfiltration, data modification, and even potential remote code execution.

## Attack Chain

1. An attacker authenticates to the Rucio instance using any supported method (userpass, x509, OIDC, SAML, SSH, GSS).
2. The attacker crafts a malicious request to the DID search endpoint (`GET /dids/<scope>/dids/search`).
3. The crafted request includes specially formatted filter keys and values designed to inject SQL code.
4. Rucio's `FilterEngine.create_postgres_query` function processes the request and directly interpolates the attacker-controlled values into a raw SQL query.
5. The injected SQL code is executed against the PostgreSQL metadata database.
6. The attacker can then perform actions such as reading sensitive data (password hashes, tokens, account details), modifying data, or attempting remote code execution.
7. If the database user has sufficient privileges, the attacker can use PostgreSQL's `COPY ... FROM PROGRAM` to execute arbitrary commands on the server.
8. Successful exploitation allows the attacker to gain complete control over the Rucio metadata.

## Impact

Successful exploitation of this SQL injection vulnerability can have severe consequences. An attacker can modify or delete data within the Rucio metadata database, potentially disrupting scientific workflows and data management processes. Furthermore, sensitive information, such as password hashes and authentication tokens, can be extracted, leading to unauthorized access to Rucio accounts and data. In the worst-case scenario, if the PostgreSQL database user has elevated privileges, the attacker could achieve remote code execution on the server hosting the database, leading to complete system compromise. The number of affected deployments is currently unknown, but any Rucio instance utilizing the `postgres_meta` plugin is vulnerable.

## Recommendation

*   Upgrade Rucio to a patched version (35.8.5, 38.5.5, 39.4.2, 40.1.1 or later) to remediate CVE-2026-29090.
*   Deploy the Sigma rule "Detect Suspicious Rucio DID Search Queries" to identify potential exploitation attempts against the DID search endpoint.
*   Monitor Rucio logs for unusual activity related to the `GET /dids/<scope>/dids/search` endpoint.
*   Restrict the privileges of the PostgreSQL database user used by Rucio to the minimum necessary for its operation to mitigate potential remote code execution.
