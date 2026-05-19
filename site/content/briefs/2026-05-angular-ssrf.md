---
title: Angular platform-server SSRF via Hostname Hijacking (CVE-2026-46417)
slug: 2026-05-angular-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in `@angular/platform-server` due to improper processing of the request URL by the server-side rendering engine, allowing attackers to redirect relative HTTP requests to attacker-controlled servers, potentially exposing internal APIs or metadata services; patch CVE-2026-46417 immediately.
date: "2026-05-19T20:31:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - angular
  - vulnerability
vendors:
  - Angular
products:
  - '@angular/platform-server (>= 22.0.0-next.0, < 22.0.0-next.12)'
  - '@angular/platform-server (>= 21.0.0-next.0, < 21.2.13)'
  - '@angular/platform-server (>= 20.0.0-next.0, < 20.3.21)'
  - '@angular/platform-server (>= 19.0.0-next.0, < 19.2.22)'
  - '@angular/platform-server (<= 18.2.14)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://github.com/advisories/GHSA-rfh7-fxqc-q52v
  - CVE-2026-46417
rules:
  - title: Detect Angular platform-server SSRF via Hostname Hijacking (CVE-2026-46417)
    description: Detects CVE-2026-46417 exploitation — attempts to pass absolute URLs to the Angular platform-server renderModule or renderApplication functions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Suspicious Host Header - Angular SSRF (CVE-2026-46417)
    description: Detects CVE-2026-46417 exploitation — attempts to manipulate the Host header with attacker-controlled domains.
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

A Server-Side Request Forgery (SSRF) vulnerability has been identified in `@angular/platform-server`. This vulnerability arises from the server-side rendering (SSR) engine's handling of request URLs. When an absolute-form URL (e.g., `http://evil.com`) is provided to the rendering engine, the internal `ServerPlatformLocation` can be manipulated. This manipulation allows an attacker to set the hostname to an attacker-controlled domain. This issue impacts versions of `@angular/platform-server` prior to the patched versions: 22.0.0-next.12, 21.2.13, 20.3.21, and 19.2.22 and also impacts versions `<= 18.2.14`. This vulnerability enables the redirection of relative `HttpClient` requests and `PlatformLocation.hostname` references to the attacker's server, potentially exposing internal APIs or metadata services.

## Attack Chain

1.  The attacker crafts a malicious URL with an absolute form (e.g., `http://evil.com`).
2.  This malicious URL is passed to the `@angular/platform-server` rendering engine's entry points (`renderModule` or `renderApplication`).
3.  The `ServerPlatformLocation` internal component processes the URL.
4.  Due to the vulnerability, `ServerPlatformLocation` is manipulated to adopt the attacker-controlled domain (`evil.com`) as the "current" hostname.
5.  The Angular application, during server-side rendering, makes a relative `HttpClient` request (e.g., `/api/internal`).
6.  This relative request, intended for the legitimate server, is now redirected to `http://evil.com/api/internal`.
7.  The attacker's server receives the redirected request, potentially containing sensitive information.
8.  The attacker gains unauthorized access to internal APIs or metadata services through the redirected request.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-46417) can lead to the exposure of sensitive internal APIs and metadata services. An attacker could potentially gain access to confidential data, modify application settings, or perform unauthorized actions on behalf of the server. This can lead to data breaches, system compromise, and reputational damage.

## Recommendation

*   Upgrade to the patched versions of `@angular/platform-server`: 22.0.0-next.12, 21.2.13, 20.3.21, or 19.2.22 to mitigate the vulnerability as noted in the advisory.
*   For developers unable to update immediately, implement strict URL validation in their server entry point (e.g., `server.ts`) as suggested in the advisory.
*   Deploy the Sigma rule "Detect Angular platform-server SSRF via Hostname Hijacking (CVE-2026-46417)" to detect potential exploitation attempts by monitoring server logs.
