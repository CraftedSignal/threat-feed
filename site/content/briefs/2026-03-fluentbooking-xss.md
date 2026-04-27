---
title: Fluent Booking WordPress Plugin Stored XSS Vulnerability
slug: 2026-03-fluentbooking-xss
description: The Fluent Booking plugin for WordPress is vulnerable to stored cross-site scripting (XSS) allowing unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses the injected page, affecting versions up to and including 2.0.01.
date: "2026-03-26T14:16:09Z"
severities:
  - high
tags:
  - wordpress
  - xss
  - cve-2026-2231
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-2231
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/37441cc0-c43c-40e4-a170-1be59e112272?source=cve
rules:
  - title: Detect Suspicious URI Parameters in WordPress
    description: Detects potential XSS attempts in URI parameters targeting WordPress sites by looking for common XSS payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress XSS via URI Parameters
    description: Detects attempts to exploit XSS vulnerabilities in WordPress through URI parameters. This rule identifies common injection patterns in cs-uri-query.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-2231 describes a stored cross-site scripting (XSS) vulnerability within the Fluent Booking WordPress plugin. This vulnerability affects all versions up to and including 2.0.01. The root cause is insufficient input sanitization and output escaping of multiple parameters handled by the plugin. An unauthenticated attacker can exploit this vulnerability to inject malicious JavaScript code into the WordPress site. The injected script executes in the context of the victim's browser when they…
