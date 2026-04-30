---
title: Ory Kratos SQL Injection Vulnerability in ListCourierMessages API
slug: 2024-01-ory-kratos-sqli
description: A SQL injection vulnerability exists in the ListCourierMessages Admin API of Ory Kratos versions prior to 26.2.0 due to flaws in its pagination implementation, allowing attackers to craft malicious tokens if the pagination secret is known or the default secret is used.
date: "2026-03-26T18:16:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ory-kratos
  - sql-injection
  - cve-2026-33503
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33503
rules:
  - title: Ory Kratos Suspicious ListCourierMessages Request
    description: Detects requests to the ListCourierMessages API with unusually long page_token parameters, potentially indicative of SQL injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Ory Kratos Potential SQL Injection in page_token
    description: Detects potential SQL injection attempts in the page_token parameter of the ListCourierMessages API based on common SQL injection syntax.
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

Ory Kratos, an identity, user management, and authentication system for cloud services, is vulnerable to SQL injection in versions prior to 26.2.0. The vulnerability resides within the ListCourierMessages Admin API and stems from flaws in its pagination implementation. The pagination tokens are encrypted using a secret configured in `secrets.pagination`. Attackers who obtain this secret can forge malicious tokens, leading to SQL injection attacks. Critically, if this configuration value remains unset, Kratos defaults to a publicly known pagination encryption secret. This allows attackers to manually generate valid malicious pagination tokens for vulnerable installations. Defenders should immediately configure a custom value for `secrets.pagination` using a cryptographically secure random secret and upgrade Kratos to version 26.2.0 or later.

## Attack Chain

1.  Attacker identifies an Ory Kratos instance running a version prior to 26.2.0.
2.  Attacker checks the Kratos configuration to determine if `secrets.pagination` is set.
3.  If `secrets.pagination` is not set, the attacker leverages the publicly known default pagination encryption secret.
4.  The attacker crafts a malicious pagination token containing SQL injection payloads. This token exploits the vulnerable pagination logic in the `ListCourierMessages` API.
5.  Attacker sends a request to the `/admin/courier/messages` endpoint with the crafted pagination token in the `page_token` parameter.
6.  The Kratos application processes the malicious token, leading to the execution of arbitrary SQL queries against the underlying database.
7.  The SQL injection allows the attacker to potentially read, modify, or delete sensitive data within the Kratos database, including user credentials, configuration settings, or other confidential information.
8.  The attacker may use the compromised data for further attacks, such as account takeover or privilege escalation.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to complete compromise of the Ory Kratos instance. This can result in unauthorized access to user accounts, disclosure of sensitive information, and potential data manipulation or deletion. The severity is high due to the potential for significant data breach and service disruption impacting all users managed by the compromised Kratos instance. The number of victims depends on the size and user base of the affected Ory Kratos deployment.

## Recommendation

*   Immediately configure a custom value for `secrets.pagination` by generating a cryptographically secure random secret within your Ory Kratos configuration (reference: Overview section).
*   Upgrade Ory Kratos to version 26.2.0 or later to patch the SQL injection vulnerability (reference: Overview section).
*   Monitor web server logs for suspicious requests to the `/admin/courier/messages` endpoint containing unusually long or malformed `page_token` parameters (create a custom rule based on this behavior).
*   Implement a Web Application Firewall (WAF) rule to block requests with suspicious SQL syntax in the `page_token` parameter targeting the `/admin/courier/messages` endpoint.
