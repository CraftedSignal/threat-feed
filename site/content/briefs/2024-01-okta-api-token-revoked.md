---
title: Okta API Token Revoked
slug: 2024-01-okta-api-token-revoked
description: Detection of Okta API token revocation events, indicating potential unauthorized access or compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
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

This alert focuses on detecting the revocation of Okta API tokens. Okta API tokens are used to authenticate and authorize applications to access Okta's APIs. When a token is revoked, it means that the token is no longer valid and can no longer be used to access Okta's APIs. This can happen for a number of reasons, including: a user manually revoking the token, an administrator revoking the token, or Okta automatically revoking the token due to inactivity or security concerns. Detecting API token revocations is crucial because it can indicate that a token has been compromised and is being used by an attacker. A revoked token could be a sign of successful lateral movement or data exfiltration attempts within the Okta environment.

## Attack Chain

1. Initial Access: An attacker gains unauthorized access to an Okta API token through methods like phishing, credential stuffing, or malware.
2. API Usage: The attacker uses the stolen API token to access Okta's APIs, potentially gathering sensitive information or modifying user accounts.
3. Anomaly Detection: Okta's security mechanisms or custom alerts identify unusual activity associated with the API token, such as access from unfamiliar locations or excessive API calls.
4. Investigation Triggered: Security personnel initiate an investigation based on the flagged anomalous activity.
5. Token Revocation: As part of the incident response process, the compromised API token is manually or automatically revoked to prevent further unauthorized access. This action generates a "system.api_token.revoke" event in the Okta system log.
6. Post-Revocation Analysis: Security teams analyze the events leading up to the token revocation to identify the root cause of the compromise and assess the scope of the attacker's activities.

## Impact

Successful compromise of an Okta API token can lead to significant damage, including unauthorized access to sensitive user data, modification of user accounts and permissions, and disruption of critical business operations. If not detected promptly, attackers can leverage compromised tokens to escalate privileges, move laterally within the Okta environment, and potentially gain access to other connected systems. A single compromised API token could affect hundreds or thousands of users, depending on the scope of access granted to the token.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect `system.api_token.revoke` events in Okta logs.
*   Investigate any detected `system.api_token.revoke` events to determine the cause of the revocation and assess the potential impact.
*   Review Okta system logs for anomalous activity prior to the token revocation to identify the source of the compromise.
*   Implement multi-factor authentication (MFA) for all Okta users to reduce the risk of credential compromise.
*   Regularly audit and review Okta API tokens to identify and revoke unused or overly permissive tokens.
