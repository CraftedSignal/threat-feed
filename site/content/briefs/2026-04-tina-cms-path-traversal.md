---
title: Tina CMS Path Traversal Vulnerability (CVE-2026-34603)
slug: 2026-04-tina-cms-path-traversal
description: Tina CMS versions before 2.2.2 are vulnerable to a path traversal attack that allows unauthorized file system access due to insufficient validation of symlinks and junction targets in media routes.
date: "2026-04-01T17:28:41Z"
severities:
  - high
tags:
  - path-traversal
  - tina-cms
  - CVE-2026-34603
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34603
rules:
  - title: Detect Tina CMS Path Traversal Attempt via HTTP Request
    description: Detects potential path traversal attempts targeting Tina CMS media routes by looking for specific path traversal sequences in HTTP request URIs.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Tina CMS Path Traversal Attempt via HTTP Request (Encoded)
    description: Detects potential path traversal attempts targeting Tina CMS media routes by looking for encoded path traversal sequences in HTTP request URIs.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Tina CMS, a headless content management system, is susceptible to a path traversal vulnerability in versions prior to 2.2.2. The vulnerability, identified as CVE-2026-34603, stems from insufficient validation of symlink and junction targets within the `@tinacms/cli` media routes. Although lexical path-traversal checks were implemented, they only validate the path string without resolving symlinks or junctions. This flaw enables attackers to bypass intended security measures and perform…
