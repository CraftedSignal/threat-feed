---
title: Budibase Stored Cross-Site Scripting Vulnerability (CVE-2026-35218)
slug: 2026-04-budibase-xss
description: A stored cross-site scripting (XSS) vulnerability in Budibase versions prior to 3.32.5 allows authenticated users with Builder access to inject malicious HTML payloads into entity names, leading to potential session cookie theft and account takeover when other Builder users open the Command Palette.
date: "2026-04-03T16:16:41Z"
severities:
  - high
tags:
  - budibase
  - xss
  - cve-2026-35218
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-35218
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35218
rules:
  - title: Budibase Suspicious Command Palette HTML
    description: Detects potential XSS exploitation in Budibase by monitoring HTTP requests for the Command Palette that contain suspicious HTML tags in the query parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Budibase Suspicious Entity Creation with HTML
    description: Detects potential XSS exploitation in Budibase by monitoring HTTP requests related to entity creation that contain suspicious HTML tags in the request body.
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

Budibase, an open-source low-code platform, is vulnerable to a stored cross-site scripting (XSS) attack. Prior to version 3.32.5, the Builder Command Palette renders entity names (tables, views, queries, automations) unsanitized, using Svelte's {@html} directive. This allows an attacker with Builder access to inject arbitrary HTML into the names of database tables, views, queries, or automations. When a Builder-role user in the same workspace opens the Command Palette (Ctrl+K), the injected…
