---
title: Cross-Site Scripting via Improper Redirect URI Validation in better-auth
slug: 2026-08-better-auth-redirect-uri-vuln
description: 'The better-auth library fails to validate redirect_uri schemes in its oidc-provider and mcp plugins, allowing attackers to inject javascript: URIs that lead to XSS and potential account takeover.'
date: "2026-08-01T13:54:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - oauth
  - cve-2026-67333
vendors:
  - better-auth
products:
  - better-auth (< 1.6.13)
  - better-auth (1.7.0-beta.0 through 1.7.0-beta.3)
cves:
  - id: CVE-2026-67333
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67333
---

The better-auth library, specifically versions prior to 1.6.13 and pre-release builds 1.7.0-beta.0 through 1.7.0-beta.3, contains a vulnerability in the oidc-provider and mcp plugins. These plugins fail to validate the scheme of redirect URIs during the registration of OAuth clients. An attacker can supply a malicious redirect URI using the 'javascript:' scheme. When an authorization server returns this URI to a consent page that improperly handles the navigation - typically by assigning the URI directly to window.location.href - the attacker's script executes within the context of the authorization server's origin. This enables the theft of session tokens and full account takeover for affected users. This vulnerability highlights the importance of strictly validating URI schemes before processing navigation in sensitive web application flows.

## Impact

Successful exploitation allows for arbitrary JavaScript execution in the origin of the authorization server. This facilitates session hijacking and account takeover of authenticated users interacting with the authorization flow. The scope includes any application utilizing the deprecated oidc-provider or mcp plugins within the affected version ranges.

## Recommendation

1. Upgrade better-auth to version 1.6.13 or later to remediate CVE-2026-67333.
2. Audit all deployments using the oidc-provider or mcp plugins to ensure redirect URIs are strictly validated against a whitelist of approved schemes (e.g., http, https).
3. Review frontend code responsible for processing OAuth consent pages to ensure navigation logic does not execute values from untrusted user inputs (i.e., avoid dynamic window.location.href assignment with unsanitized URI parameters).
