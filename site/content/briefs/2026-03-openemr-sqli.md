---
title: OpenEMR Blind SQL Injection Vulnerability in Patient Search (CVE-2026-29187)
slug: 2026-03-openemr-sqli
description: OpenEMR versions prior to 8.0.0.3 are susceptible to a blind SQL injection vulnerability in the Patient Search functionality, allowing authenticated attackers to execute arbitrary SQL commands by manipulating HTTP parameter keys.
date: "2026-03-25T23:17:09Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sqli
  - openemr
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-29187
  - https://github.com/openemr/openemr/security/advisories/GHSA-2r7h-xm8v-m872
rules:
  - title: Detect OpenEMR SQL Injection Attempt via Parameter Key Manipulation
    description: Detects potential SQL injection attempts in OpenEMR by monitoring for suspicious characters or keywords in the parameter keys of requests to the Patient Search functionality.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenEMR SQL Injection Attempt via URL Encoding
    description: Detects SQL injection attempts in OpenEMR Patient Search functionality via URL encoded characters in the query string.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenEMR, a widely used open-source electronic health records and medical practice management application, has a critical security flaw. Specifically, versions prior to 8.0.0.3 contain a blind SQL injection vulnerability affecting the Patient Search functionality located at `/interface/new/new_search_popup.php`. Authenticated attackers can exploit this vulnerability, identified as CVE-2026-29187, by manipulating HTTP parameter keys during patient searches. Successful exploitation allows…
