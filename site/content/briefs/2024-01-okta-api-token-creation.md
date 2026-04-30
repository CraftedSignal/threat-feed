---
title: Okta API Token Creation
slug: 2024-01-okta-api-token-creation
description: Detection of Okta API token creation events which can indicate malicious persistence activity.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
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

The creation of Okta API tokens is a legitimate administrative function, but can also be abused by malicious actors to establish persistence within an Okta environment. Monitoring for the creation of these tokens, especially when performed by unexpected users or under unusual circumstances, is crucial for identifying potential security breaches. Okta API tokens allow for programmatic access to Okta resources, making them a valuable asset for attackers seeking to maintain access or perform unauthorized actions. Defenders should prioritize monitoring for these events to quickly identify and respond to potentially malicious activity.

## Attack Chain

1.  An attacker gains unauthorized access to an Okta account with sufficient privileges (e.g., Super Administrator).
2.  The attacker authenticates to the Okta Admin Console.
3.  The attacker navigates to the Security > API > Tokens section of the Okta Admin Console.
4.  The attacker creates a new API token with broad or specific permissions.
5.  Okta logs the `system.api_token.create` event.
6.  The attacker uses the newly created API token to programmatically access Okta resources.
7.  The attacker may leverage the API token for various malicious activities, such as user enumeration, group manipulation, or application access.
8.  The attacker maintains persistent access to the Okta environment even if their initial access is revoked.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, modification of user accounts and permissions, and potentially complete control over the Okta environment. The impact can range from data breaches and service disruptions to complete compromise of identity management. The number of victims and sectors targeted depends on the scope of the compromised Okta environment.

## Recommendation

*   Deploy the Sigma rule "Okta API Token Created" to your SIEM to detect API token creation events (logsource: okta, service: okta).
*   Investigate any detected `system.api_token.create` events to verify the legitimacy of the token creation.
*   Review Okta system logs for unusual administrative activity preceding the API token creation event (logsource: okta, service: okta).
*   Implement multi-factor authentication (MFA) for all Okta administrator accounts to reduce the risk of unauthorized access.
