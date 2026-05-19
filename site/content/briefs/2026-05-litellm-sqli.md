---
title: LiteLLM SQL Injection Vulnerability (CVE-2025-45809)
slug: 2026-05-litellm-sqli
description: A SQL Injection vulnerability (CVE-2025-45809) in LiteLLM versions prior to 1.81.0 allows unauthenticated attackers to potentially steal database contents and read server files via time-based blind SQL injection in the `/key/block` and `/key/unblock` endpoints.
date: "2026-05-19T04:01:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - sqli
  - sql-injection
  - CVE-2025-45809
vendors:
  - Litellm
products:
  - LiteLLM (< 1.81.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://sploitus.com/exploit?id=1D95AE51-553A-551C-AC83-B19834AFF512
  - https://nvd.nist.gov/vuln/detail/CVE-2025-45809
  - https://huntr.com/bounties/3e6e4d40-b06a-4f54-a3ed-cc93584b12f3
  - https://security.snyk.io/vuln/SNYK-PYTHON-LITELLM-10598343
  - https://github.com/shadia0/Patienc/blob/main/litellm/SQL_injection.md
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=1D95AE51-553A-551C-AC83-B19834AFF512
ioc_counts:
  url: 1
rules:
  - title: Detects CVE-2025-45809 Exploitation Attempt — LiteLLM SQL Injection via /key/block
    description: Detects CVE-2025-45809 exploitation attempt — suspicious HTTP POST requests to /key/block endpoint in LiteLLM with potential SQL injection payloads in the key parameter
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2025-45809 Exploitation Attempt — LiteLLM SQL Injection via /key/unblock
    description: Detects CVE-2025-45809 exploitation attempt — suspicious HTTP POST requests to /key/unblock endpoint in LiteLLM with potential SQL injection payloads in the key parameter
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A SQL Injection vulnerability, tracked as CVE-2025-45809, affects LiteLLM versions prior to 1.81.0. The vulnerability resides in the `/key/block` and `/key/unblock` endpoints. A public exploit is available, demonstrating that an attacker can leverage time-based blind SQL injection via the `key` parameter to extract sensitive database information and potentially read files from the server. Successful exploitation could lead to data exfiltration and unauthorized access to internal systems. It is crucial for organizations using vulnerable versions of LiteLLM to upgrade to version 1.81.0 or later, or apply the suggested mitigations.

## Attack Chain

1. The attacker identifies a vulnerable LiteLLM instance running a version prior to 1.81.0.
2. The attacker crafts a malicious HTTP request targeting either the `/key/block` or `/key/unblock` endpoint.
3. The crafted request includes a SQL injection payload within the `key` parameter, designed for time-based blind injection.
4. The LiteLLM application processes the request without proper sanitization, executing the injected SQL code against the underlying database.
5. The attacker monitors the response time of the server. The time delay is used to infer the results of the SQL query due to the blind nature of the injection.
6. Through repeated requests and refined payloads, the attacker progressively extracts database contents, such as usernames, passwords, and API keys.
7. The attacker uses extracted credentials to gain unauthorized access to other services or resources.
8. The attacker may read files from the server.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2025-45809) could allow an unauthenticated attacker to steal sensitive database contents, including API keys and user credentials. While the CVSS score is rated as medium (5.4), the impact can be high if the compromised data grants access to critical systems or exposes sensitive customer information. Organizations using affected versions of LiteLLM are urged to apply the necessary patches or mitigations to prevent potential data breaches and unauthorized access.

## Recommendation

*   Upgrade LiteLLM to version 1.81.0 or later to remediate CVE-2025-45809.
*   Implement input validation on the `key` parameter in the `/key/block` and `/key/unblock` endpoints.
*   Deploy a Web Application Firewall (WAF) to filter out requests containing SQL injection patterns, as recommended in the advisory.
*   Monitor web server logs for suspicious activity targeting the `/key/block` and `/key/unblock` endpoints to detect potential exploitation attempts (see webserver log source in the rules below).
