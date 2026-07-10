---
title: HAPI FHIR Credential Leakage via Improper URL Prefix Matching
slug: 2024-01-hapi-fhir-credential-leak
description: HAPI FHIR Core is vulnerable to authentication credential leakage due to improper URL prefix matching on HTTP redirects, allowing attackers to intercept credentials by hosting a domain that is a prefix of a configured FHIR server URL.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - hapi-fhir
  - credential-leakage
  - redirect
  - CVE-2026-34359
vendors:
  - HAPI
products:
  - HAPI FHIR Core
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://github.com/advisories/GHSA-fgv2-4q4g-wc35
iocs:
  - type: url
    value: http://tx.fhir.org.attacker.com
  - type: url
    value: http://tx.fhir.org
ioc_counts:
  url: 2
rules:
  - title: Detect Suspicious FHIR Redirect
    description: Detects potential exploitation of the HAPI FHIR credential leakage vulnerability by identifying HTTP redirects to unusual domains.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - webserver
      - linux
  - title: Detect FHIR Server Subdomain Redirect
    description: Detects web server requests resulting in HTTP 302 redirects to a domain that contains a configured FHIR server name as a subdomain, indicating potential credential leakage.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - webserver
      - linux
rules_count: 2
---

HAPI FHIR Core versions prior to 6.9.4 are vulnerable to an authentication credential leakage issue. The vulnerability resides in the `ManagedWebAccessUtils.getServer()` function, which uses `String.startsWith()` to match request URLs against configured server URLs. Due to the lack of a proper host boundary check, an attacker can register a domain that is a prefix of a legitimate FHIR server URL (e.g., `http://tx.fhir.org.attacker.com` matching `http://tx.fhir.org`). When the application follows a redirect to this attacker-controlled domain, sensitive credentials such as Bearer tokens, Basic authentication credentials, or API keys are inadvertently sent to the attacker. This issue affects deployments that configure server authentication in `fhir-settings.json` and make outbound HTTP requests to terminology servers. The vulnerability was introduced due to the removal of a host-equality check for redirects in `SimpleHTTPClient`.

## Attack Chain

1. The application makes an HTTP request to a configured FHIR server (e.g., `http://tx.fhir.org/ValueSet/$expand`).
2. The legitimate server responds with an HTTP 302 redirect to an attacker-controlled domain that shares a prefix with the legitimate server (e.g., `http://tx.fhir.org.attacker.com/capture`).
3. The HTTP client (either `SimpleHTTPClient` or `ManagedFhirWebAccessor` with OkHttpClient) follows the redirect.
4. The `ManagedWebAccessUtils.getServer()` function is called to determine if authentication headers should be added to the request.
5. Due to the `startsWith()` check, the attacker's domain matches the configured server URL.
6. The `ServerDetailsPOJOHTTPAuthProvider.getHeaders()` function retrieves configured credentials (Bearer token, Basic auth, or API key).
7. The HTTP client adds the retrieved authentication headers to the redirected request.
8. The request, including the sensitive credentials, is sent to the attacker-controlled server. The attacker captures these credentials.

## Impact

Successful exploitation of this vulnerability allows an attacker to steal authentication credentials, including Bearer tokens, Basic authentication passwords, API keys, and custom authentication headers configured for FHIR terminology servers. Stolen credentials enable the attacker to impersonate legitimate users, potentially accessing or modifying clinical terminology data on the legitimate FHIR server. This can lead to unauthorized data access, data manipulation, and potential compliance violations. The vulnerability impacts any FHIR Validator deployment that configures server authentication and makes outbound HTTP requests, making it a widespread concern in healthcare IT. It may also allow TLS downgrade.

## Recommendation

*   Apply the vendor-supplied patch to upgrade to HAPI FHIR Core version 6.9.4 or later to remediate CVE-2026-34359.
*   Deploy the Sigma rule `Detect Suspicious FHIR Redirect` to identify potential exploitation attempts based on redirects to unusual domains.
*   Monitor web server logs for HTTP redirects to domains containing the names of configured FHIR servers as a subdomain using the `Detect FHIR Server Subdomain Redirect` Sigma rule.
*   Implement proper URL host boundary validation in `ManagedWebAccessUtils.getServer()` and `ManagedWebAccess.isLocal()` as described in the advisory.
