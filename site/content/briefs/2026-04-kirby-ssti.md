---
title: Kirby CMS Server-Side Template Injection via Double Template Resolution
slug: 2026-04-kirby-ssti
description: A server-side template injection (SSTI) vulnerability exists in Kirby CMS within the option rendering feature due to double template resolution in option fields (checkboxes, color, multiselect, select, radio, tags, or toggles) when using options from a query or API with untrusted values, potentially allowing attackers to inject malicious queries.
date: "2026-04-23T21:24:37Z"
severities:
  - high
tags:
  - ssti
  - kirby
  - template-injection
vendors:
  - getkirby
products:
  - cms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-jcjw-58rv-c452
rules:
  - title: Detect Kirby CMS SSTI Attempt via HTTP Request
    description: Detects potential SSTI attempts in Kirby CMS by identifying HTTP requests containing template syntax in the query parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Kirby CMS SSTI Attempt via POST Request Body
    description: Detects potential SSTI attempts in Kirby CMS by identifying POST requests containing template syntax in the body.
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

A server-side template injection (SSTI) vulnerability has been identified in Kirby CMS affecting sites using option fields (checkboxes, color, multiselect, select, radio, tags, or toggles) with options sourced from queries or APIs where the values cannot be fully trusted. This vulnerability, discovered and reported by @offset, stems from a double resolution of templates within the options rendering logic. An attacker with Panel access or through user interaction can inject malicious query…
