---
title: Okta Policy Rule Modification or Deletion
slug: 2024-01-29-okta-policy-rule-modification
description: An Okta policy rule was modified or deleted, potentially weakening security controls.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - okta
  - identity
  - policy
  - attack.impact
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
rules:
  - title: Okta Policy Rule Modified or Deleted
    description: Detects when an Okta Policy Rule is Modified or Deleted.
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - okta
      - okta
  - title: Okta Policy Rule Update with MFA Disabled
    description: Detects modifications to Okta policy rules that disable or weaken MFA requirements.
    platform: sigma
    severity: high
    tactics:
      - impact
      - privilege_escalation
    data_sources:
      - okta
      - okta
rules_count: 2
---

Okta is a widely used identity and access management platform. Threat actors may target Okta configurations to weaken an organization's security posture. This activity involves modifications or deletions of policy rules within Okta. Such changes can reduce the effectiveness of multi-factor authentication (MFA) requirements, bypass access controls, or disable security logging. Detection of these changes is crucial to maintaining a strong security baseline and preventing unauthorized access to sensitive resources. Defenders should monitor Okta logs for unexpected or unauthorized policy rule modifications or deletions.

## Attack Chain

1. Initial Access: The attacker gains unauthorized access to an Okta administrator account, possibly through credential theft or phishing.
2. Authentication: The attacker authenticates to the Okta admin dashboard using the compromised credentials.
3. Discovery: The attacker enumerates existing policy rules to understand the current security configuration.
4. Modification: The attacker modifies an existing policy rule to weaken its security controls. This could involve disabling MFA, bypassing location restrictions, or altering group membership requirements.
5. Deletion: Alternatively, the attacker deletes a policy rule entirely, effectively removing a layer of security.
6. Privilege Escalation: With weakened or removed policy rules, the attacker escalates privileges, gaining access to sensitive applications or data.
7. Lateral Movement: The attacker leverages the compromised Okta environment to move laterally within the organization's network, accessing additional systems and resources.
8. Impact: The attacker achieves their final objective, such as data exfiltration, financial fraud, or system disruption, due to the weakened security posture.

## Impact

Successful modification or deletion of Okta policy rules can severely compromise an organization's security. Consequences include unauthorized access to sensitive data, privilege escalation, lateral movement, and ultimately, data breaches or financial loss. The number of affected users and systems depends on the scope of the compromised policy rules and the attacker's subsequent actions. Organizations in all sectors that rely on Okta for identity management are vulnerable.

## Recommendation

*   Deploy the "Okta Policy Rule Modified or Deleted" Sigma rule to your SIEM to detect unauthorized changes (rule reference).
*   Review Okta system logs regularly for policy rule modifications or deletions, focusing on unusual source IPs or user agents.
*   Implement multi-factor authentication (MFA) for all Okta administrator accounts to prevent unauthorized access (reference: Okta documentation).
*   Enforce the principle of least privilege for Okta administrator roles, limiting the number of users who can modify policy rules.
*   Alert on eventType `policy.rule.update` or `policy.rule.delete` in Okta logs using the provided Sigma rule (rule reference).
