---
title: CI4MS Unauthenticated .env Overwrite Vulnerability (CVE-2026-39393)
slug: 2024-01-30-ci4ms-takeover
description: CI4MS versions before 0.31.4.0 are vulnerable to unauthenticated takeover due to a flawed install route guard that allows overwriting the .env file with attacker-controlled database credentials when the database is temporarily unreachable.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - CVE-2026-39393
  - CI4MS
  - CodeIgniter
  - Remote Code Execution
  - Unauthenticated Access
vendors:
  - CI4MS
products:
  - CI4MS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-39393
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39393
rules:
  - title: Detect CI4MS Install Route Access
    description: Detects unauthorized access attempts to the CI4MS installation route, potentially indicating exploitation of CVE-2026-39393.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect CI4MS Env Overwrite
    description: Detects POST requests to the CI4MS installation route that attempt to modify the .env file, potentially indicating exploitation of CVE-2026-39393.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CI4MS, a CodeIgniter 4-based CMS skeleton, is vulnerable to a critical security flaw (CVE-2026-39393) in versions prior to 0.31.4.0. The vulnerability stems from an insufficient install route guard mechanism. This guard, designed to prevent unauthorized access to the setup wizard after installation, relies on a combination of a volatile cache check (`cache('settings')`) and the presence of the `.env` file. When the database becomes temporarily unreachable, leading to a cache miss (either due to TTL expiry or manual cache clearing), the route guard fails open. This failure enables an unauthenticated attacker to access the setup wizard and overwrite the `.env` file with maliciously crafted database credentials. Successful exploitation leads to complete application takeover. The vulnerability was patched in version 0.31.4.0.

## Attack Chain

1. The target CI4MS instance experiences a database outage or becomes temporarily unreachable.
2. The `cache('settings')` check in the install route guard fails due to a cache miss caused by the database outage.
3. The flawed logic in the route guard incorrectly determines that the application is not yet installed.
4. An unauthenticated attacker accesses the `/install` route, bypassing the intended security controls.
5. The attacker interacts with the setup wizard, providing malicious database credentials.
6. The application proceeds to overwrite the existing `.env` file with the attacker-supplied database configuration.
7. The attacker gains full administrative access to the CI4MS application using the newly configured database credentials.
8. The attacker can then execute arbitrary code, modify content, and compromise sensitive data within the CI4MS application.

## Impact

Successful exploitation of CVE-2026-39393 allows an unauthenticated attacker to achieve full application takeover of CI4MS instances running versions prior to 0.31.4.0. This can lead to complete data breaches, website defacement, and potential compromise of the underlying server. The severity is critical due to the ease of exploitation and the potential for widespread damage. The number of affected systems depends on the number of CI4MS installations that have not been upgraded to version 0.31.4.0 or later.

## Recommendation

*   Immediately upgrade all CI4MS installations to version 0.31.4.0 or later to patch CVE-2026-39393.
*   Implement network monitoring for unusual access attempts to the `/install` route on CI4MS instances.
*   Deploy the Sigma rule `Detect CI4MS Install Route Access` to detect unauthorized access attempts to the vulnerable installation route.
*   Review webserver logs for POST requests to the `/install` route with parameters suggestive of database configuration changes. Use the Sigma rule `Detect CI4MS Env Overwrite` as a starting point.
