---
title: Smart Post Show WordPress Plugin PHP Object Injection Vulnerability
slug: 2026-04-smart-post-show-rce
description: The Smart Post Show WordPress plugin versions 3.0.12 and earlier are vulnerable to PHP Object Injection via deserialization of untrusted input in the import_shortcodes() function, potentially leading to remote code execution if a suitable POP chain is present.
date: "2026-04-14T06:17:10Z"
severities:
  - high
tags:
  - wordpress
  - php
  - object-injection
  - rce
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Access Software
cves:
  - id: CVE-2026-3017
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3017
rules:
  - title: Detect WordPress Plugin Deserialization Attempt
    description: Detects potential PHP object injection attempts via crafted requests to WordPress plugins.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Detect Potential WordPress POP Chain Trigger
    description: Detects potential Property-Oriented Programming (POP) chain execution attempts in WordPress plugins or themes.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Smart Post Show WordPress plugin, specifically the Post Grid, Post Carousel & Slider, and List Category Posts components, contains a PHP Object Injection vulnerability. This flaw affects all versions up to and including 3.0.12. The vulnerability resides in the `import_shortcodes()` function, where the deserialization of untrusted input occurs. This vulnerability requires an authenticated attacker with administrative privileges or higher. Successful exploitation requires the presence of a…
