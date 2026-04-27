---
title: Okta Network Zone Deactivation or Deletion
slug: 2024-01-26-okta-network-zone-changes
description: An Okta network zone was deactivated or deleted, potentially indicating malicious activity aimed at bypassing security controls.
date: "2024-01-26T18:22:00Z"
severities:
  - medium
tags:
  - okta
  - network-zone
  - impact
vendors:
  - Okta
products:
  - Okta Identity Engine
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_network_zone_deactivated_or_deleted.yml
rules:
  - title: Okta Network Zone Deactivated or Deleted
    description: Detects when an Okta Network Zone is Deactivated or Deleted.
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - okta
      - okta
  - title: Okta Admin Activity - Network Zone Deletion
    description: Detects when an Okta Network Zone is deleted by an admin user.
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - okta
      - okta
rules_count: 2
---

Okta network zones define trusted network boundaries for user access. These zones are configured with specific IP address ranges and can be used to restrict access to applications and resources. When an Okta network zone is deactivated or deleted, it can indicate a malicious actor attempting to weaken security policies, potentially allowing unauthorized access from untrusted locations. This activity is relevant for defenders because it may signal a breach in progress or preparation for future…
