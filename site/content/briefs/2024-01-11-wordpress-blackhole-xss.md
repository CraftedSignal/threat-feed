---
title: Blackhole for Bad Bots WordPress Plugin Stored XSS Vulnerability
slug: 2024-01-11-wordpress-blackhole-xss
description: The Blackhole for Bad Bots WordPress plugin through version 3.8 is vulnerable to stored cross-site scripting (XSS) via the User-Agent HTTP header, allowing unauthenticated attackers to inject arbitrary web scripts that execute when an administrator views the plugin's admin page.
date: "2026-03-26T05:16:40Z"
severities:
  - medium
tags:
  - wordpress
  - xss
  - plugin
  - cve-2026-4329
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4329
rules:
  - title: Detect WordPress Blackhole Bad Bots XSS Attempt via User-Agent
    description: Detects requests with User-Agent headers containing common XSS patterns targeting CVE-2026-4329.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Blackhole Bad Bots Admin Page Access
    description: Detects access to the Blackhole Bad Bots admin page, which, when combined with malicious User-Agent, could indicate exploitation of CVE-2026-4329.
    platform: sigma
    severity: low
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Blackhole for Bad Bots plugin for WordPress, up to and including version 3.8, contains a stored cross-site scripting (XSS) vulnerability. The vulnerability stems from insufficient input sanitization and output escaping of the User-Agent HTTP header when capturing bot data. Specifically, the plugin uses `sanitize_text_field()` which strips HTML tags but does not escape HTML entities. This data is then stored using `update_option()` and later displayed on the Bad Bots log page. The stored…
