---
title: Everest Forms WordPress Plugin PHP Object Injection Vulnerability
slug: 2026-04-everest-forms-rce
description: The Everest Forms plugin for WordPress is vulnerable to PHP Object Injection (CVE-2026-3296) in versions up to 3.4.3, allowing unauthenticated attackers to execute arbitrary code by injecting serialized PHP objects via form fields.
date: "2026-04-08T02:16:04Z"
severities:
  - critical
tags:
  - wordpress
  - php
  - object-injection
  - rce
  - cve-2026-3296
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-3296
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3296
rules:
  - title: Detect Suspicious unserialize Call in Everest Forms
    description: Detects calls to the unserialize function in the Everest Forms plugin without specifying allowed classes, indicating a potential PHP Object Injection vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Form Submission with Serialized Data
    description: Detects POST requests to WordPress form submission endpoints containing serialized PHP objects.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Everest Forms plugin for WordPress, a widely used form builder, contains a critical PHP Object Injection vulnerability (CVE-2026-3296) affecting versions up to and including 3.4.3. This vulnerability stems from the insecure deserialization of user-supplied data within the `html-admin-page-entries-view.php` file. Specifically, the plugin uses PHP's `unserialize()` function on form entry metadata stored in the `wp_evf_entrymeta` table without specifying allowed classes, creating an…
