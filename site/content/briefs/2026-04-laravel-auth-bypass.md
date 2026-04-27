---
title: Laravel Passport Authentication Bypass Vulnerability (CVE-2026-39976)
slug: 2026-04-laravel-auth-bypass
description: Laravel Passport versions 13.0.0 before 13.7.1 contain an authentication bypass vulnerability (CVE-2026-39976) where machine-to-machine tokens can authenticate as a real user due to improper validation of the JWT sub claim.
date: "2026-04-09T17:16:31Z"
severities:
  - high
tags:
  - cve-2026-39976
  - laravel
  - oauth2
  - authentication bypass
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1586
    technique_name: Compromise Accounts
cves:
  - id: CVE-2026-39976
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39976
rules:
  - title: Detect Laravel Passport Authentication Bypass Attempt
    description: Detects requests where a machine-to-machine token authenticates as a regular user, indicative of CVE-2026-39976 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1586
      - T1586.002
    data_sources:
      - webserver
      - linux
  - title: Detect Errors Authenticating with Machine Credentials
    description: Detects 401 errors authenticating with client credentials, possibly an attempted authentication bypass
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1586
      - T1586.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Laravel Passport, an OAuth2 server implementation for Laravel, is vulnerable to an authentication bypass (CVE-2026-39976) in versions 13.0.0 up to, but not including, 13.7.1. The vulnerability stems from the `league/oauth2-server` library, where the JWT `sub` claim is set to the client identifier for `client_credentials` tokens, as there is no associated user. Subsequently, the token guard uses this client identifier to retrieve user information via `retrieveById()` without proper validation…
