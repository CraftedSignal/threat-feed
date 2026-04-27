---
title: ChurchCRM Stored XSS Vulnerability (CVE-2026-35574)
slug: 2026-04-churchcrm-xss
description: A stored XSS vulnerability in ChurchCRM versions before 6.5.3 allows authenticated users with note-adding permissions to inject arbitrary JavaScript code, potentially leading to session hijacking and privilege escalation.
date: "2026-04-07T17:16:32Z"
severities:
  - high
tags:
  - cve-2026-35574
  - xss
  - churchcrm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-35574
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35574
  - https://github.com/ChurchCRM/CRM/security/advisories/GHSA-cx82-8xrh-7f5c
ioc_counts:
  url: 1
rules:
  - title: Detect ChurchCRM XSS via Note Editor
    description: Detects potential XSS attacks against ChurchCRM Note Editor by looking for script tags or event handlers in the request URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect ChurchCRM XSS via Note Editor - URL Encoded
    description: Detects potential XSS attacks against ChurchCRM Note Editor with URL encoded javascript in the request URI.
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

ChurchCRM, an open-source church management system, is vulnerable to a stored Cross-Site Scripting (XSS) flaw. This vulnerability, identified as CVE-2026-35574, resides in the Note Editor of versions prior to 6.5.3. Authenticated users possessing note-adding permissions can inject malicious JavaScript code into notes. When other users, including administrators, view these notes, the injected script executes within their browsers. This can result in session hijacking, privilege escalation, and…
