---
title: free5gc UDR Improper Path Validation Allows Unauthenticated Access to Traffic Influence Subscriptions
slug: 2026-04-free5gc-udr-path-validation
description: An improper path validation vulnerability exists in the free5gc UDR service, allowing unauthenticated attackers with access to the 5G Service Based Interface (SBI) to read Traffic Influence Subscriptions.
date: "2026-04-14T20:01:43Z"
severities:
  - high
tags:
  - free5GC
  - UDR
  - path-validation
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-x5r2-r74c-3w28
ioc_counts:
  url: 1
rules:
  - title: Detect free5GC UDR Path Traversal Attempt
    description: Detects attempts to exploit the free5GC UDR path traversal vulnerability by monitoring for 404 responses with JSON content in the response body.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect free5GC UDR Subscription Creation with Suspicious Notification URI
    description: Detects attempts to create Traffic Influence Subscriptions with a suspicious notification URI.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

An improper path validation vulnerability in the free5gc UDR (User Data Repository) service allows unauthenticated attackers with network access to the 5G Service Based Interface (SBI) to read Traffic Influence Subscriptions. The vulnerability, present in versions up to 1.4.2, stems from a missing `return` statement after an HTTP 404 response is sent for an invalid path. This allows the request to continue processing and return subscription data despite the invalid path. An attacker can exploit…
