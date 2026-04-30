---
title: Okta User Account Created
slug: 2024-01-23-okta-user-created
description: Detection of new user account creation in Okta, which could indicate malicious activity related to credential access.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - okta
  - identity
  - user-creation
  - credential-access
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://developer.okta.com/docs/reference/api/event-types/
rules:
  - title: Okta - New User Created via API
    description: Detects new user creation events in Okta logs specifically initiated via the Okta API.
    platform: sigma
    severity: informational
    tactics:
      - credential-access
    data_sources:
      - okta
      - okta
  - title: Okta - New User Created with Specific Role
    description: Detects new user creation events in Okta logs where a specific role is assigned during creation.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
      - privilege_escalation
    data_sources:
      - okta
      - okta
rules_count: 2
---

This alert detects the creation of new user accounts within an Okta environment. While legitimate user creation is common, malicious actors may create accounts to gain unauthorized access to resources, escalate privileges, or establish persistence within the network. Monitoring for anomalous user creation activity, such as accounts created outside of normal business hours or with suspicious naming conventions, is crucial for identifying potential security breaches. Reviewing the source IP and administrator account used for the user creation can also provide valuable context.

## Attack Chain

1.  An attacker gains initial access to an Okta administrator account, potentially through phishing, credential stuffing, or exploiting a vulnerability.
2.  The attacker authenticates to the Okta admin portal.
3.  The attacker navigates to the user management section within the Okta admin console.
4.  The attacker creates a new user account, potentially mimicking an existing user or using a generic naming convention.
5.  The attacker assigns the new user account specific roles and permissions, potentially granting elevated privileges.
6.  The attacker may use the newly created account to access sensitive applications and data within the Okta-protected environment.
7.  The attacker uses the compromised or newly created account to maintain persistence within the Okta environment.

## Impact

A successful attack leading to unauthorized user creation can result in significant data breaches, privilege escalation, and unauthorized access to sensitive applications and resources. This could lead to financial loss, reputational damage, and compliance violations. The impact depends on the permissions granted to the created user and the applications they can access.

## Recommendation

*   Deploy the Sigma rule "New Okta User Created" to your SIEM to detect user creation events and tune for your environment.
*   Investigate any detected user creation events for legitimacy, focusing on the source IP address and the administrator account used.
*   Implement multi-factor authentication (MFA) for all Okta administrator accounts to mitigate the risk of credential compromise.
*   Review Okta event logs regularly for suspicious activity, including user creation, permission changes, and application access.
*   Establish baseline user creation patterns to identify anomalous behavior, such as accounts created outside of normal business hours.
