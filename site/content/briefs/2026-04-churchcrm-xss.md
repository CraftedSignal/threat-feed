---
title: ChurchCRM Stored XSS Vulnerability in Person Property Management
slug: 2026-04-churchcrm-xss
description: A stored cross-site scripting (XSS) vulnerability in ChurchCRM versions prior to 7.0.0 allows authenticated users to inject arbitrary JavaScript code via dynamically assigned person properties, leading to potential session hijacking or account compromise when other users view the affected profile.
date: "2026-04-08T12:00:00Z"
severities:
  - high
tags:
  - xss
  - web-application
  - churchcrm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2023-38766
    cvss: 5.4
    epss: 0.00209
  - id: CVE-2026-35576
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35576
rules:
  - title: Detect ChurchCRM XSS Attempt via Property Value
    description: Detects potential XSS attacks in ChurchCRM by monitoring for script tags or event handlers within dynamically assigned person property values.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
  - title: Detect ChurchCRM XSS in HTTP Response
    description: Detects potential XSS attacks in ChurchCRM reflected in the HTTP response body. This rule is looking for responses containing script tags or event handlers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
rules_count: 2
---

ChurchCRM, an open-source church management system, is vulnerable to a stored cross-site scripting (XSS) attack affecting versions prior to 7.0.0. This vulnerability resides within the Person Property Management subsystem and stems from insufficient input sanitization when handling dynamically assigned person properties. An authenticated attacker can inject malicious JavaScript code, which is then persistently stored in the database. When other users view the compromised person's profile or…
