---
title: GLPI Cross-Site Scripting Vulnerability (CVE-2026-25932)
slug: 2026-04-glpi-xss
description: CVE-2026-25932 is a cross-site scripting vulnerability in GLPI versions 0.60 to before 10.0.24, where an authenticated technician user can store a malicious XSS payload within supplier fields, potentially leading to arbitrary code execution in the context of other users' browsers.
date: "2026-04-06T15:17:06Z"
severities:
  - medium
tags:
  - xss
  - glpi
  - cve-2026-25932
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-25932
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25932
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-m627-945g-x7xh
rules:
  - title: Detect GLPI Suspicious HTTP Referer
    description: Detects requests to GLPI with a suspicious HTTP Referer header, potentially indicating XSS attacks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect GLPI XSS Payload in HTTP Request
    description: Detects HTTP requests to GLPI containing common XSS payload patterns in the query string.
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

CVE-2026-25932 is a stored cross-site scripting (XSS) vulnerability affecting GLPI, a free asset and IT management software package. The vulnerability exists in versions 0.60 up to, but not including, 10.0.24. An authenticated technician user, with the necessary privileges, can inject a malicious XSS payload into the supplier fields within the GLPI application. This payload is then stored in the database and executed when other users with access to the affected supplier data view the…
