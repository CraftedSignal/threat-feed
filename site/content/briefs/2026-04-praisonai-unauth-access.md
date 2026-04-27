---
title: PraisonAI Unauthenticated Agent Activity Exposure (CVE-2026-39889)
slug: 2026-04-praisonai-unauth-access
description: PraisonAI versions prior to 4.5.115 expose agent activity without authentication due to improperly secured A2U event stream endpoints, potentially allowing unauthorized access to sensitive agent information.
date: "2026-04-08T21:17:01Z"
severities:
  - high
tags:
  - cve-2026-39889
  - information-disclosure
  - web-application
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
cves:
  - id: CVE-2026-39889
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39889
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-f292-66h9-fpmf
ioc_counts:
  url: 1
rules:
  - title: Detect Unauthenticated Access to PraisonAI A2U Endpoints
    description: Detects unauthenticated HTTP GET requests to PraisonAI A2U endpoints, indicating potential exploitation of CVE-2026-39889.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
  - title: Detect Access to PraisonAI A2U Endpoints - Wildcard
    description: Detects unauthenticated HTTP GET requests to PraisonAI A2U endpoints, indicating potential exploitation of CVE-2026-39889, using a wildcard for event streams.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, is vulnerable to unauthenticated information disclosure in versions prior to 4.5.115. The vulnerability, identified as CVE-2026-39889, stems from the A2U (Agent-to-User) event stream server exposing sensitive agent activity without proper authentication. The `create_a2u_routes()` function registers several endpoints, including `/a2u/info`, `/a2u/subscribe`, `/a2u/events/{stream_name}`, `/a2u/events/sub/{id}`, and `/a2u/health`, without implementing…
