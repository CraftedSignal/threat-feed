---
title: WordPress Widgets for Social Photo Feed Plugin Stored XSS Vulnerability
slug: 2026-04-wordpress-xss
description: The Widgets for Social Photo Feed plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the 'feed_data' parameter, allowing unauthenticated attackers to inject arbitrary web scripts in pages that will execute when a user accesses the injected page.
date: "2026-04-04T09:16:20Z"
severities:
  - medium
actors:
  - Unauthenticated Attacker
tags:
  - wordpress
  - xss
  - cve-2026-5425
  - plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-5425
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5425
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/2584097a-8955-41c7-b009-c6502fe8b99b?source=cve
rules:
  - title: Detect WordPress Social Photo Feed XSS Attempt
    description: Detects potential attempts to exploit the Stored XSS vulnerability (CVE-2026-5425) in the Widgets for Social Photo Feed WordPress plugin by looking for script tags or event handlers within the feed_data parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Social Photo Feed XSS in POST Request
    description: Detects potential attempts to exploit the Stored XSS vulnerability (CVE-2026-5425) in the Widgets for Social Photo Feed WordPress plugin by looking for script tags or event handlers within the feed_data parameter in POST requests.
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

The Widgets for Social Photo Feed plugin for WordPress, versions up to and including 1.7.9, contains a stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-5425). This vulnerability stems from insufficient input sanitization and output escaping of the 'feed_data' parameter keys. An unauthenticated attacker can exploit this flaw by injecting malicious JavaScript code into the WordPress database. When a user visits a page containing a vulnerable widget, the injected script executes within…
