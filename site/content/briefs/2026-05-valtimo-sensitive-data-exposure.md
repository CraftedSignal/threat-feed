---
title: Valtimo Sensitive Data Exposure via Excessive HTTP Request/Response Logging (CVE-2026-44516)
slug: 2026-05-valtimo-sensitive-data-exposure
description: The `LoggingRestClientCustomizer` in Valtimo's `web` module automatically intercepts all outgoing HTTP calls and logs the full request/response body and headers, potentially exposing sensitive information like credentials, personal data, and session tokens via error messages logged at ERROR level (CVE-2026-44516).
date: "2026-05-11T16:13:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sensitive-data-exposure
  - logging
  - valtimo
vendors:
  - Ritense
products:
  - Valtimo
references:
  - https://github.com/advisories/GHSA-3jh5-rr2q-xfv7
  - CVE-2026-44516
rules:
  - title: Detect Valtimo HttpClientErrorException Logging of Sensitive Data
    description: Detects Valtimo logging HttpClientErrorException messages that may contain sensitive data like API keys, tokens or personal information due to excessive logging (CVE-2026-44516).
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1592.002
    data_sources:
      - application
      - valtimo
rules_count: 1
---

The `LoggingRestClientCustomizer` component in Valtimo versions 12.4.0 through 12.32.0 and 13.0.0 through 13.25.0 exhibits a sensitive data exposure vulnerability (CVE-2026-44516). This component, designed to log outgoing HTTP calls made via Spring's `RestClient`, captures and logs the full request body, response body, and response headers. Critically, when an error response is received, this information is included in the `HttpClientErrorException` message. This exception is then logged at ERROR level by Spring's default exception handling, overriding any DEBUG log level configurations set by the application. This means that even in production environments where debug logging is disabled, sensitive information can still be exposed to anyone with access to the application logs, logging aggregation tools, or the Valtimo logging module (available to Valtimo admins since version 12.5.0). This vulnerability was resolved in versions 12.33.0 and 13.26.0 by removing the request/response data from the `HttpClientErrorException` constructor and limiting the full report to DEBUG level logging only.

## Attack Chain

1. An administrator configures Valtimo to interact with an external API (e.g., ZGW services) that requires authentication.
2. The Valtimo application makes an HTTP request to the external API, including sensitive data (e.g., API key, JWT token) in the request body or headers.
3. The external API returns an error response (e.g., 401 Unauthorized, 500 Internal Server Error).
4. The `LoggingRestClientCustomizer` intercepts the error response and constructs an `HttpClientErrorException` containing the full request and response details, including sensitive data.
5. Spring's default exception handling logs the `HttpClientErrorException` message at ERROR level.
6. An attacker gains access to the application logs (e.g., via compromised server access, unauthorized access to logging aggregation tools, or the Valtimo logging module).
7. The attacker reviews the logs and extracts the sensitive data (e.g., API key, JWT token, personal data) from the logged `HttpClientErrorException` message.
8. The attacker uses the leaked authentication credentials to impersonate the Valtimo application against the external API, gaining unauthorized access to resources or performing actions on behalf of the application.

## Impact

Successful exploitation of this vulnerability could lead to the exposure of sensitive information, including authentication credentials (JWT tokens, API keys, OAuth tokens), personal data (BSN, email addresses, case details), and session tokens. This information could be used to compromise external APIs integrated with Valtimo, potentially leading to data breaches, unauthorized access to resources, or impersonation of the Valtimo application. The impact is heightened due to the exposure of this data to administrators through the built-in logging module since Valtimo version 12.5.0.

## Recommendation

*   Upgrade Valtimo to version 12.33.0 or 13.26.0 to remediate CVE-2026-44516, where the sensitive data is removed from the `HttpClientErrorException` constructor.
*   Until upgrading, restrict access to application logs and the Valtimo logging module as described in the advisory's Mitigation section.
*   Deploy the Sigma rule "Detect Valtimo HttpClientErrorException Logging of Sensitive Data" to identify instances where sensitive data is being logged in error messages, alerting on potential exposures.
