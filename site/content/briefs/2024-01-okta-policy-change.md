---
title: Okta Policy Modification or Deletion Detected
slug: 2024-01-okta-policy-change
description: An Okta policy was modified or deleted, potentially indicating unauthorized changes to security configurations within the Okta identity management platform by a malicious actor or insider.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - identity
  - okta
  - policy
  - attack.impact
vendors:
  - Okta
products:
  - Okta Identity Cloud
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
rules:
  - title: Okta Policy Modified or Deleted
    description: Detects when an Okta policy is modified or deleted.
    platform: sigma
    severity: low
    tactics:
      - impact
    data_sources:
      - okta
      - okta
  - title: Okta Policy Modified by Uncommon User Agent
    description: Detects Okta policy modifications originating from an unusual user agent.
    platform: sigma
    severity: medium
    tactics:
      - impact
      - privilege_escalation
    data_sources:
      - okta
      - okta
rules_count: 2
---

This alert identifies modifications or deletions of Okta policies, which govern authentication, authorization, and access control within the Okta Identity Cloud platform. While legitimate administrators routinely update policies, unauthorized changes can weaken security postures and grant malicious actors elevated privileges or bypass security controls. The source event indicates a potential compromise or insider threat activity within the Okta environment. Because Okta serves as a critical identity provider for many organizations, any unauthorized change to its policies can have far-reaching consequences. Detecting policy changes is crucial for maintaining the integrity and security of the Okta environment and preventing potential breaches. The targeted scope includes all Okta-managed applications and resources protected by the modified or deleted policy.

## Attack Chain

1. **Initial Access:** The attacker gains access to an Okta administrator account, either through compromised credentials (e.g., phishing, credential stuffing) or insider access.
2. **Authentication:** The attacker authenticates to the Okta admin console using the compromised or legitimate administrator account.
3. **Policy Enumeration:** The attacker identifies target Okta policies to modify or delete using the Okta admin console or API.
4. **Policy Modification/Deletion:** The attacker modifies or deletes the targeted Okta policy through the Okta admin console or API. This generates an `policy.lifecycle.update` or `policy.lifecycle.delete` event.
5. **Privilege Escalation (Potential):** By modifying policies, the attacker may escalate privileges, granting themselves or other unauthorized users access to sensitive applications and resources.
6. **Lateral Movement (Potential):** With escalated privileges, the attacker moves laterally within the Okta environment, accessing other applications and resources.
7. **Data Exfiltration/Damage (Potential):** The attacker leverages the compromised Okta environment to exfiltrate sensitive data or cause damage to connected systems.

## Impact

A successful Okta policy modification or deletion can have significant consequences. Unauthorized policy changes can weaken security controls, allowing attackers to bypass authentication mechanisms, escalate privileges, and gain unauthorized access to sensitive applications and data. This could lead to data breaches, financial loss, and reputational damage. The impact depends on the scope of the affected policy and the applications it protects. The number of victims could range from a few individuals to the entire organization, depending on the scope of the compromised policy.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect Okta policy modifications or deletions (`policy.lifecycle.update`, `policy.lifecycle.delete` event types).
*   Investigate any detected policy changes to verify their legitimacy and identify the user responsible.
*   Review Okta administrator account activity for any signs of compromise or unauthorized access.
*   Implement multi-factor authentication (MFA) for all Okta administrator accounts to prevent unauthorized access.
*   Regularly review and audit Okta policies to ensure they are configured securely and in accordance with security best practices.
