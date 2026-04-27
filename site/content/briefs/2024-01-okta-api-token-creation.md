---
title: Okta API Token Creation
slug: 2024-01-okta-api-token-creation
description: Detection of Okta API token creation events which can indicate malicious persistence activity.
date: "2024-01-03T12:00:00Z"
severities:
  - medium
tags:
  - persistence
  - okta
vendors:
  - Okta
products:
  - Okta Identity Cloud
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_api_token_created.yml
rules:
  - title: Okta API Token Created
    description: Detects when an API token is created in Okta
    platform: sigma
    severity: medium
    tactics:
      - persistence
    data_sources:
      - okta
      - okta
  - title: Okta API Token Created by Unusual IP
    description: Detects when an API token is created from an IP address not normally associated with administrative activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    data_sources:
      - okta
      - okta
rules_count: 2
---

The creation of Okta API tokens is a legitimate administrative function, but can also be abused by malicious actors to establish persistence within an Okta environment. Monitoring for the creation of these tokens, especially when performed by unexpected users or under unusual circumstances, is crucial for identifying potential security breaches. Okta API tokens allow for programmatic access to Okta resources, making them a valuable asset for attackers seeking to maintain access or perform…
