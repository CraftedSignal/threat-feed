---
title: Heimdall Authorization Bypass via Path Normalization Mismatch
slug: 2024-01-02-heimdall-auth-bypass
description: Heimdall is vulnerable to an authorization bypass due to a path normalization mismatch between Heimdall and downstream components, potentially leading to unauthorized access and privilege escalation.
date: "2024-01-02T12:00:00Z"
severities:
  - high
tags:
  - authorization-bypass
  - path-normalization
  - cloud
vendors:
  - dadrus
products:
  - heimdall
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-3q34-rx83-r6mq
rules:
  - title: Detect HTTP Requests with Dot-Segments
    description: Detects HTTP requests containing dot-segments (..) in the URI, which may indicate path traversal attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect URL Encoded Dot-Segments in HTTP Requests
    description: Detects HTTP requests containing URL-encoded dot-segments (%2e%2e) in the URI, which may indicate path traversal attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Heimdall, a cloud-native security proxy, is susceptible to an authorization bypass vulnerability. This issue arises from a discrepancy in how Heimdall handles request paths compared to downstream components. Specifically, Heimdall performs rule matching on the raw, non-normalized request path, while downstream components might normalize dot-segments (e.g., `/user/../admin`) according to RFC 3986. This can lead to Heimdall authorizing a request based on the raw path, whereas the downstream…
