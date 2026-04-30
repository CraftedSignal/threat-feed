---
title: Okta Application Sign-On Policy Modified or Deleted
slug: 2024-01-okta-sign-on-policy-changes
description: Attackers may modify or delete Okta application sign-on policies to weaken security controls, potentially leading to unauthorized access and data breaches.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - identity
  - okta
  - policy-tampering
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
rules:
  - title: Okta Application Sign-On Policy Modified or Deleted
    description: Detects when an application Sign-on Policy is modified or deleted.
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - okta
      - okta
  - title: Okta Policy Modified by Non-Admin User
    description: Detects policy modifications when the actor is not a designated admin user.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - okta
      - okta
rules_count: 2
---

Okta application sign-on policies control how users authenticate to applications integrated with Okta. An attacker who gains administrative access to an Okta tenant can modify or delete these policies, effectively weakening or bypassing multi-factor authentication (MFA) requirements and other security controls. This allows unauthorized access to sensitive applications and data. While this activity itself is not initial access, it represents a significant escalation of privileges and a deliberate attempt to subvert existing security measures within the Okta environment. Detection of these changes is critical to identify potential breaches early and prevent further damage.

## Attack Chain

1. An attacker gains unauthorized access to an Okta administrator account through compromised credentials or other means.
2. The attacker authenticates to the Okta admin dashboard.
3. The attacker navigates to the "Security" section and then to "Authentication Policies".
4. The attacker identifies the target application sign-on policy to modify or delete.
5. To modify, the attacker changes the policy rules, such as disabling MFA requirements or allowing access from untrusted locations.
6. Alternatively, to delete, the attacker selects the policy and confirms its removal.
7. The attacker's actions are logged as "application.policy.sign_on.update" or "application.policy.sign_on.rule.delete" events in the Okta system log.
8. Unauthorized users can now access applications protected by the modified or deleted policy, potentially leading to data exfiltration or other malicious activities.

## Impact

Successful modification or deletion of Okta application sign-on policies can severely compromise an organization's security posture. This can lead to unauthorized access to sensitive applications and data, resulting in data breaches, financial losses, and reputational damage. The number of affected users and applications depends on the scope of the compromised policies.

## Recommendation

*   Deploy the Sigma rule "Okta Application Sign-On Policy Modified or Deleted" to your SIEM and tune for your environment to detect changes to sign-on policies (rule reference).
*   Monitor the Okta system log for "application.policy.sign_on.update" and "application.policy.sign_on.rule.delete" events to identify suspicious activity (log source reference).
*   Implement strong access controls and MFA for Okta administrator accounts to prevent unauthorized policy modifications (best practice).
*   Regularly review Okta application sign-on policies to ensure they are properly configured and meet security requirements (best practice).
