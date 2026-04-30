---
title: Query Monitor WordPress Plugin Vulnerable to Reflected XSS (CVE-2026-4267)
slug: 2024-01-query-monitor-xss
description: The Query Monitor WordPress plugin is vulnerable to reflected cross-site scripting (XSS) due to insufficient input sanitization and output escaping of the '$_SERVER['REQUEST_URI']' parameter, allowing unauthenticated attackers to inject arbitrary web scripts.
date: "2026-03-31T12:16:31Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - wordpress
  - xss
  - reflected-xss
  - cve-2026-4267
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-4267
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4267
rules:
  - title: Detect Query Monitor XSS Attempt via URI
    description: Detects potential XSS attacks targeting the Query Monitor plugin by monitoring the request URI for common XSS payloads.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Query Monitor XSS Attempt via Request URI (Alternative)
    description: Detects potential XSS attacks targeting the Query Monitor plugin by monitoring the request URI for base64 encoded payloads, which is a common obfuscation technique.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Query Monitor plugin for WordPress, a developer tool panel, is susceptible to a reflected Cross-Site Scripting (XSS) vulnerability. Identified as CVE-2026-4267, this flaw exists in all versions up to and including 3.20.3. The vulnerability arises from the plugin's failure to adequately sanitize input and escape output related to the `$_SERVER['REQUEST_URI']` parameter. An unauthenticated attacker can exploit this by injecting malicious web scripts into pages, posing a threat to users who…
