---
title: Heimdall Host Matching Case-Sensitivity Vulnerability
slug: 2024-01-02-heimdall-case-sensitivity
description: Heimdall performs case-sensitive host matching, which can lead to policy bypass because HTTP hostnames are case-insensitive, potentially leading to unauthorized access, data modification, or privilege escalation if the request host is part of the rule.
date: "2024-01-02T12:00:00Z"
severities:
  - high
tags:
  - defense-evasion
  - policy-bypass
  - access-control
vendors:
  - dadrus
products:
  - heimdall
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-72h4-mxfc-jx37
rules:
  - title: Detect HTTP Requests with Mixed-Case Host Headers
    description: Detects HTTP requests where the Host header contains mixed-case characters, potentially indicating an attempt to bypass case-sensitive access controls.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Usage of Insecure Heimdall Flags
    description: Detects command-line arguments indicating the use of insecure Heimdall configurations, such as skipping secure default rule enforcement.
    platform: sigma
    severity: high
    tactics:
      - configuration
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Heimdall, a Go-based access management system, is susceptible to a case-sensitivity vulnerability in its host matching mechanism. HTTP hostnames are case-insensitive, but Heimdall performs host matching in a case-sensitive manner. Discovered and reported in April 2026, this discrepancy can result in Heimdall failing to match a rule for a request host that differs only in letter casing. Version 0.16.0 and later enforce secure defaults and refuse to start with an "allow all" configuration unless…
