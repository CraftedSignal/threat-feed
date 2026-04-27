---
title: Ory Kratos SQL Injection Vulnerability in ListCourierMessages API
slug: 2024-01-ory-kratos-sqli
description: A SQL injection vulnerability exists in the ListCourierMessages Admin API of Ory Kratos versions prior to 26.2.0 due to flaws in its pagination implementation, allowing attackers to craft malicious tokens if the pagination secret is known or the default secret is used.
date: "2026-03-26T18:16:30Z"
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

Ory Kratos, an identity, user management, and authentication system for cloud services, is vulnerable to SQL injection in versions prior to 26.2.0. The vulnerability resides within the ListCourierMessages Admin API and stems from flaws in its pagination implementation. The pagination tokens are encrypted using a secret configured in `secrets.pagination`. Attackers who obtain this secret can forge malicious tokens, leading to SQL injection attacks. Critically, if this configuration value remains…
