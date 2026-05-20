---
title: phpMyFAQ Authentication Bypass via Default Empty API Token
slug: 2026-05-phpmyfaq-auth-bypass
description: phpMyFAQ versions 4.1.2 and earlier are vulnerable to an authentication bypass via a default empty API token, allowing unauthenticated users to create and modify FAQ entries, categories, and questions via the REST API.
date: "2026-05-20T15:47:14Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - authentication-bypass
  - phpmyfaq
  - rest-api
  - injection
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ (<= 4.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-gp95-j463-vv28
rules:
  - title: Detect phpMyFAQ Authentication Bypass via Empty Token
    description: Detects phpMyFAQ authentication bypass attempts by monitoring for HTTP requests with an empty `x-pmf-token` header to sensitive API endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect phpMyFAQ Faq Modification via Empty Token
    description: Detects phpMyFAQ Faq modification attempts by monitoring for HTTP requests with an empty `x-pmf-token` header to the Faq update endpoint.
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

phpMyFAQ versions 4.1.2 and earlier contain an authentication bypass vulnerability. The issue stems from the default configuration where the `api.apiClientToken` setting is initialized to an empty string during installation. The `hasValidToken()` function fails to properly differentiate between a missing token and an explicitly empty token provided by an attacker. Consequently, by sending an HTTP request with an empty `x-pmf-token` header, an attacker can bypass authentication checks and gain unauthorized access to API endpoints intended for administrative purposes, such as creating and modifying FAQ entries and categories. This vulnerability affects any phpMyFAQ instance running with the default configuration, as the REST API is enabled by default.

## Attack Chain

1. The attacker identifies a phpMyFAQ instance running with the default configuration (API enabled, empty API token).
2. The attacker crafts an HTTP POST request to `/api/v4.0/faq/create` to create a new FAQ entry.
3. The attacker includes the `x-pmf-token` header in the request, setting its value to an empty string.
4. The server-side `hasValidToken()` function evaluates `'' !== ''` as `false`, bypassing the authentication check.
5. The request proceeds to the `faq/create` endpoint, allowing the attacker to inject arbitrary content into the FAQ database.
6. The attacker crafts a similar request to `/api/v4.0/category` to create a new category.
7. The empty `x-pmf-token` header bypasses authentication.
8. The injected FAQ and category content is now publicly accessible, potentially leading to phishing, SEO spam, or distribution of malicious links.

## Impact

This authentication bypass vulnerability allows unauthenticated attackers to create and modify content within phpMyFAQ installations running with the default configuration. This impacts organizations that rely on phpMyFAQ as a knowledge base, as attackers can inject malicious or misleading information, leading to potential phishing attacks, SEO spam, reputation damage, and the spread of malicious links. The vulnerability is present in all installations where the administrator has not explicitly set a non-empty API client token, which is the default state after installation, impacting potentially a significant number of deployments.

## Recommendation

*   Apply available patches or upgrade to a secure version of phpMyFAQ to remediate the vulnerability.
*   Explicitly set a strong, non-empty value for the `api.apiClientToken` configuration setting to prevent the authentication bypass.
*   Deploy the Sigma rule "Detect phpMyFAQ Authentication Bypass via Empty Token" to detect exploitation attempts in real-time.
*   Monitor web server logs for POST requests to `/api/v4.0/faq/create` and `/api/v4.0/category` with an empty `x-pmf-token` header to identify potential exploitation attempts.
