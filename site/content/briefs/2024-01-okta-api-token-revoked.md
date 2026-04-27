---
title: Okta API Token Revoked
slug: 2024-01-okta-api-token-revoked
description: Detection of Okta API token revocation events, indicating potential unauthorized access or compromise.
date: "2024-01-03T12:00:00Z"
severities:
  - medium
tags:
  - okta
  - api
  - token
  - revocation
  - identity
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_api_token_revoked.yml
rules:
  - title: Okta API Token Revoked
    description: Detects when an Okta API Token is revoked.
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - okta
      - okta
  - title: Okta API Token Revoked by User
    description: Detects when an Okta API Token is revoked, and identifies the actor involved in the revocation.
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - okta
      - okta
rules_count: 2
---

This alert focuses on detecting the revocation of Okta API tokens. Okta API tokens are used to authenticate and authorize applications to access Okta's APIs. When a token is revoked, it means that the token is no longer valid and can no longer be used to access Okta's APIs. This can happen for a number of reasons, including: a user manually revoking the token, an administrator revoking the token, or Okta automatically revoking the token due to inactivity or security concerns. Detecting API…
