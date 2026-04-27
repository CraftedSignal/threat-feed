---
title: Emmett Web Framework Path Traversal Vulnerability (CVE-2026-39847)
slug: 2026-04-emmett-path-traversal
description: Emmett web framework versions 2.5.0 to before 2.8.1 are vulnerable to path traversal attacks (CVE-2026-39847), allowing attackers to read arbitrary files outside the intended assets directory using manipulated URLs.
date: "2026-04-07T22:16:23Z"
severities:
  - critical
tags:
  - path-traversal
  - web-application
  - emmett
  - cve-2026-39847
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-39847
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39847
  - https://github.com/emmett-framework/emmett/security/advisories/GHSA-pr46-2v3c-5356
rules:
  - title: Detect Emmett Path Traversal Attempts
    description: Detects path traversal attempts targeting the /__emmett__/ path in Emmett web framework.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Deep Path Traversal in Emmett Web Framework
    description: This rule detects potential deep path traversal attempts within the /__emmett__/ directory, specifically looking for multiple instances of '../' to identify unusual access patterns.
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

The Emmett web framework, a full-stack Python framework, is susceptible to a path traversal vulnerability affecting versions 2.5.0 to prior to 2.8.1. Specifically, the RSGI static handler for Emmett's internal assets (/__emmett__ paths) does not properly sanitize user-supplied input, leading to CVE-2026-39847. By crafting malicious URLs containing "../" sequences, an unauthenticated attacker can bypass directory restrictions and access sensitive files residing outside the designated assets…
