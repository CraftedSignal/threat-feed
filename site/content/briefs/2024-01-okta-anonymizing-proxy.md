---
title: Okta User Session Start via Anonymizing Proxy Service
slug: 2024-01-okta-anonymizing-proxy
description: Detection of Okta user sessions initiated through anonymizing proxy services, potentially indicating malicious activity or attempts to evade security controls.
date: "2024-01-02T12:00:00Z"
severities:
  - high
tags:
  - identity
  - okta
  - proxy
  - defense-evasion
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection
  - https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_user_session_start_via_anonymised_proxy.yml
rules:
  - title: Okta User Session Start Via Anonymizing Proxy
    description: Detects Okta user sessions started through anonymizing proxies.
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
    techniques:
      - T1562.006
    data_sources:
      - okta
      - okta
  - title: Okta User Session Start - Anonymizing Proxy with Geolocation Mismatch
    description: Detects Okta user sessions started through anonymizing proxies, coupled with a significant geographical mismatch between the user's profile and the proxy's exit node.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1562.006
    data_sources:
      - okta
      - okta
rules_count: 2
---

This threat brief focuses on detecting Okta user session starts that originate from anonymizing proxy services. Anonymizing proxies can be used by malicious actors to mask their true IP addresses and location, making it more difficult to trace their activities. The use of such proxies during Okta authentication is suspicious because it bypasses geographical restrictions and may indicate compromised credentials. Defenders should be aware that legitimate users may occasionally use anonymizing…
