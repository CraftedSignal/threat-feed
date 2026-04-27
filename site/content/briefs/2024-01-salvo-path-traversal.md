---
title: Salvo Web Framework Path Traversal Vulnerability
slug: 2024-01-salvo-path-traversal
description: Salvo web framework versions 0.39.0 through 0.89.2 are vulnerable to Path Traversal and Access Control Bypass, allowing unauthenticated external attackers to bypass proxy routing constraints and access unintended backend paths.
date: "2026-03-24T00:16:29Z"
severities:
  - high
tags:
  - path-traversal
  - access-control-bypass
  - web-framework
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33242
rules:
  - title: Detect Salvo Path Traversal Attempt via URL
    description: Detects attempts to exploit CVE-2026-33242 in Salvo web framework by identifying '../' sequences in the URL.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Salvo Path Traversal Attempt via HTTP Request
    description: Detects attempts to exploit CVE-2026-33242 in Salvo web framework by identifying '../' sequences in the request URI.
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

Salvo, a Rust web framework, is vulnerable to a path traversal and access control bypass in versions 0.39.0 through 0.89.2. This vulnerability, identified as CVE-2026-33242, resides within the `salvo-proxy` component. The flaw allows unauthenticated, remote attackers to circumvent proxy routing restrictions and gain access to backend resources that should be protected. The root cause is the `encode_url_path` function's failure to properly sanitize "../" sequences within URLs. This leads to the…
