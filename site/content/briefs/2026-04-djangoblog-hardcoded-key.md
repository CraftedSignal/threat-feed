---
title: liangliangyy DjangoBlog Hardcoded Cryptographic Key Vulnerability (CVE-2026-6580)
slug: 2026-04-djangoblog-hardcoded-key
description: CVE-2026-6580 describes a vulnerability in liangliangyy DjangoBlog up to version 2.1.0.0 where manipulation of the 'key' argument in the Amap API Call Handler leads to the use of a hard-coded cryptographic key, enabling remote exploitation.
date: "2026-04-19T23:16:33Z"
severities:
  - high
tags:
  - cve-2026-6580
  - djangoblog
  - hardcoded-key
  - web-application
cves:
  - id: CVE-2026-6580
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6580
  - https://github.com/3em0/cve_repo/blob/main/DjangoBlog/Vuln-5-Hardcoded-Amap-API-Key.md
  - https://vuldb.com/vuln/358215
rules:
  - title: Detect DjangoBlog Amap API Call with Suspicious Key Manipulation
    description: Detects potential exploitation of CVE-2026-6580 by monitoring for HTTP requests to owntracks/views.py with unusual or suspicious 'key' parameters, which could indicate an attempt to trigger the use of a hardcoded cryptographic key.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to DjangoBlog owntracks/views.py
    description: Detects access to the DjangoBlog owntracks/views.py endpoint, which may indicate reconnaissance or exploitation attempts related to CVE-2026-6580
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical security vulnerability, CVE-2026-6580, has been identified in liangliangyy DjangoBlog, specifically versions up to 2.1.0.0. The flaw resides within the Amap API Call Handler in the `owntracks/views.py` file. By manipulating the `key` argument during API calls, a remote attacker can force the application to use a hard-coded cryptographic key. This vulnerability allows unauthorized access or modification of data that relies on this key for security. The exploit is publicly available…
