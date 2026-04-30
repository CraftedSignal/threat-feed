---
title: Contact Form by Supsystic WordPress Plugin SSTI Vulnerability (CVE-2026-4257)
slug: 2026-03-ssti-wordpress
description: The Contact Form by Supsystic WordPress plugin is vulnerable to Server-Side Template Injection (SSTI) via the `cfsPreFill` parameter, leading to unauthenticated Remote Code Execution (RCE).
date: "2026-03-30T22:16:20Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - ssti
  - wordpress
  - rce
  - twig
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-4257
    cvss: 9.8
    epss: 0.2424
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4257
rules:
  - title: Detect Suspicious Contact Form by Supsystic Requests
    description: Detects suspicious GET requests to WordPress containing the 'cfsPreFill' parameter, indicative of potential Server-Side Template Injection attempts targeting the Contact Form by Supsystic plugin.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Undefined Filter Callback Registration via Twig
    description: Detects requests attempting to register undefined filter callbacks via Twig, a common technique for exploiting SSTI vulnerabilities.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Contact Form by Supsystic plugin, a popular WordPress plugin, is susceptible to a critical Server-Side Template Injection (SSTI) vulnerability, identified as CVE-2026-4257. This vulnerability affects all versions up to and including 1.7.36. The root cause lies in the plugin's use of the Twig template engine (`Twig_Loader_String`) without proper sandboxing. This, combined with the `cfsPreFill` functionality, allows unauthenticated attackers to inject arbitrary Twig expressions into form…
