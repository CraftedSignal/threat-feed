---
title: Auth0-PHP SDK Cookie Forging Vulnerability (CVE-2026-34236)
slug: 2026-04-auth0-php-cookie-forging
description: Auth0-PHP SDK versions 8.0.0 to before 8.19.0 encrypt cookies with insufficient entropy, potentially allowing attackers to brute-force the encryption key and forge session cookies.
date: "2026-04-01T18:16:30Z"
severities:
  - high
tags:
  - cve-2026-34236
  - auth0
  - php
  - cookie-forging
  - session-hijacking
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
cves:
  - id: CVE-2026-34236
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34236
  - https://github.com/auth0/auth0-PHP/releases/tag/8.19.0
  - https://github.com/auth0/auth0-PHP/security/advisories/GHSA-w3wc-44p4-m4j7
rules:
  - title: Detect Auth0 PHP Session Cookie Manipulation Attempts
    description: Detects attempts to manipulate Auth0 PHP session cookies, potentially indicating an attempt to exploit CVE-2026-34236.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
  - title: Detect Auth0 PHP Session Cookie Length Anomaly
    description: Detects Auth0 PHP session cookies with unusually long or short lengths, potentially indicating forged cookies.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Auth0-PHP SDK, a PHP library for Auth0 Authentication and Management APIs, contains a vulnerability (CVE-2026-34236) affecting versions 8.0.0 to before 8.19.0. The insufficient entropy used in cookie encryption within these versions creates a significant security risk.  Attackers could potentially exploit this vulnerability by brute-forcing the encryption key used to protect session cookies. Successful exploitation would allow an attacker to forge session cookies, gaining unauthorized…
