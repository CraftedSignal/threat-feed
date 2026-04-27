---
title: liangliangyy DjangoBlog Authentication Bypass Vulnerability (CVE-2026-6577)
slug: 2026-04-djangoblog-auth-bypass
description: A critical authentication bypass vulnerability in liangliangyy DjangoBlog up to version 2.1.0.0 (CVE-2026-6577) allows remote attackers to inject arbitrary GPS data without authentication via the logtracks endpoint, potentially leading to data manipulation and unauthorized access.
date: "2026-04-19T20:16:28Z"
severities:
  - critical
tags:
  - cve-2026-6577
  - djangoblog
  - authentication-bypass
  - gps-injection
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6577
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6577
  - https://github.com/3em0/cve_repo/blob/main/DjangoBlog/Vuln-2-Unauthenticated-GPS-Data-Injection.md
  - https://vuldb.com/vuln/358212
rules:
  - title: Detect Suspicious GPS Data Injection
    description: Detects potential exploitation of the DjangoBlog authentication bypass by monitoring requests to the logtracks endpoint with suspicious parameters indicative of GPS data injection.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized Access to logtracks Endpoint
    description: Detects unauthorized attempts to access the logtracks endpoint, potentially indicating an attempt to exploit the authentication bypass vulnerability.
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

CVE-2026-6577 is an authentication bypass vulnerability affecting liangliangyy DjangoBlog versions up to 2.1.0.0. The vulnerability exists within an unknown function of the `owntracks/views.py` file related to the `logtracks` endpoint. Due to missing authentication, a remote attacker can inject arbitrary GPS data without proper authorization. This can lead to manipulation of location data, unauthorized access to location-based features, and potentially further compromise of the application. A…
