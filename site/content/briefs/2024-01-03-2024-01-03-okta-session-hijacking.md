---
title: Okta Session Hijacking via Multiple Device Token Hashes
slug: 2024-01-03-okta-session-hijacking
description: Detection of multiple device token hashes and source IPs for a single Okta session, indicating potential session hijacking and unauthorized access to Okta resources.
date: "2024-01-03T18:41:22Z"
severities:
  - medium
tags:
  - okta
  - session-hijacking
  - credential-access
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
  - https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy
  - https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection
  - https://support.okta.com/help/s/article/session-hijacking-attack-definition-damage-defense?language=en_US
  - https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security
  - https://www.elastic.co/security-labs/starter-guide-to-understanding-okta
rules:
  - title: Okta - Multiple Device Token Hashes for Single Session
    description: Detects multiple device token hashes for a single Okta session, indicating potential session hijacking.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
  - title: Okta - Multiple Client IPs for Single Session
    description: Detects multiple client IPs for a single Okta session, which might indicate session hijacking.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This threat brief addresses the risk of Okta session hijacking, where adversaries may steal session cookies or tokens to gain unauthorized access to Okta resources. The alert focuses on detecting anomalous Okta sessions characterized by multiple device token hashes and source IP addresses associated with a single authenticated user. This activity may indicate that an authenticated session has been compromised and is being replayed from different devices or networks. Defenders should be aware of…
