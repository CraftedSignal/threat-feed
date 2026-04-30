---
title: LinkAce Server-Side Request Forgery Vulnerability (CVE-2026-33953)
slug: 2024-01-linkace-ssrf
description: LinkAce versions prior to 2.5.3 are vulnerable to server-side request forgery (SSRF), allowing an authenticated user to trigger server-side requests to internal services by referencing internal hostnames.
date: "2026-03-27T22:16:21Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - ssrf
  - linkace
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33953
rules:
  - title: LinkAce - Suspicious Internal Hostname Request
    description: Detects requests to internal hostnames in LinkAce web server logs, indicating potential SSRF attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: LinkAce - Suspicious Request to Private IP Address
    description: Detects requests to private IP addresses which LinkAce is supposed to block.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

LinkAce, a self-hosted archive for collecting website links, is vulnerable to a Server-Side Request Forgery (SSRF) vulnerability in versions prior to 2.5.3. This flaw, identified as CVE-2026-33953, stems from the application's insufficient validation of user-supplied hostnames. Although direct requests to private IP literals are blocked, the application still performs server-side requests to internal resources when referenced through an internal hostname. An authenticated user can exploit this…
