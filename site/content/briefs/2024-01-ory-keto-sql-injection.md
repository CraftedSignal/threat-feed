---
title: Ory Keto SQL Injection Vulnerability via GetRelationships API (CVE-2026-33505)
slug: 2024-01-ory-keto-sql-injection
description: Ory Keto versions prior to 26.2.0 are vulnerable to SQL injection via the GetRelationships API due to flaws in its pagination implementation, enabling attackers with knowledge of the pagination secret (or the default secret) to craft malicious tokens leading to arbitrary SQL query execution.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - vulnerability
  - ory-keto
  - cve-2026-33505
vendors:
  - Ory
products:
  - Keto
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33505
rules:
  - title: Detect Suspicious GetRelationships API Requests with Long Pagination Tokens
    description: Detects requests to the GetRelationships API with unusually long pagination tokens, potentially indicating an attempt to inject malicious SQL.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Ory Keto GetRelationships API Requests with Potential SQL Injection Payloads
    description: Detects requests to the GetRelationships API containing potential SQL injection keywords in the pagination token.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Ory Keto, an open-source authorization server designed for managing permissions at scale, is susceptible to a SQL injection vulnerability (CVE-2026-33505) affecting versions prior to 26.2.0. This vulnerability resides within the GetRelationships API due to insecure pagination token handling. The application uses a secret configured in `secrets.pagination` to encrypt pagination tokens. However, if this configuration is absent, it defaults to a publicly known hard-coded secret. An attacker who knows the secret can craft malicious pagination tokens, enabling SQL injection. This impacts organizations where the GetRelationships API is accessible, the attacker can inject a raw pagination token, and the `secrets.pagination` value is either not set or known. This allows an attacker to execute arbitrary SQL queries against the Ory Keto database, potentially compromising sensitive data and control over the authorization server.

## Attack Chain

1. The attacker identifies an Ory Keto instance running a version prior to 26.2.0.
2. The attacker determines that the `secrets.pagination` configuration value is not set on the target Ory Keto instance, enabling the default hardcoded secret.
3. The attacker crafts a malicious SQL payload designed to be injected into the GetRelationships API.
4. The attacker generates a valid-looking pagination token using the known default `secrets.pagination` secret, embedding the malicious SQL payload within the token.
5. The attacker sends a request to the GetRelationships API with the forged pagination token.
6. The Ory Keto application processes the request and decrypts the pagination token, unknowingly passing the malicious SQL payload to the database query.
7. The database executes the attacker's SQL query.
8. The attacker gains unauthorized access to sensitive information or executes arbitrary database commands.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-33505) in Ory Keto can have severe consequences. An attacker could potentially gain unauthorized access to sensitive permission data, modify access control policies, or even compromise the entire authorization server. This can lead to privilege escalation, data breaches, and complete control over the systems relying on Ory Keto for authorization. The CVSS v3.1 base score for this vulnerability is rated as 7.2 (High), highlighting the significant risk it poses to organizations using affected versions of Ory Keto.

## Recommendation

*   Immediately configure a custom value for `secrets.pagination` by generating a cryptographically secure random secret to mitigate CVE-2026-33505.
*   Upgrade Keto to version 26.2.0 or later to patch CVE-2026-33505, addressing the underlying SQL injection vulnerability.
*   Monitor web server logs for suspicious requests to the GetRelationships API containing unusual pagination tokens to detect potential exploitation attempts.
*   Implement rate limiting on the GetRelationships API to reduce the impact of potential SQL injection attacks.
