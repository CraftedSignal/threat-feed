---
title: GitHub Owner Role Granted to User
slug: 2024-01-github-owner-role-granted
description: Detection of a member being granted the organization owner role in GitHub, potentially indicating unauthorized privilege escalation and persistence by an attacker.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - github
  - persistence
  - privilege-escalation
vendors:
  - GitHub
products:
  - GitHub
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/persistence_organization_owner_role_granted.toml
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/techniques/T1098/003/
  - https://attack.mitre.org/tactics/TA0003/
  - https://attack.mitre.org/tactics/TA0004/
rules:
  - title: GitHub Owner Role Granted To User
    description: Detects when a user is granted the organization owner role in GitHub, indicating potential privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
      - T1098.003
    data_sources:
      - webserver
      - github
  - title: GitHub Organization Member Role Change
    description: Detects any change in a GitHub organization member's role via audit logs.
    platform: sigma
    severity: low
    tactics:
      - account_access
    data_sources:
      - webserver
      - github
rules_count: 2
---

This alert focuses on detecting unauthorized elevation of privileges within a GitHub organization. Specifically, it identifies instances where a member is granted the "owner" role, which provides administrative-level privileges. The rule leverages GitHub audit logs to monitor changes in user roles, triggering an alert when a member's role is updated to "admin". Such changes can signify malicious activity, such as an attacker attempting to establish persistence or gain broader access to sensitive data and settings within the organization. This detection rule is based on Elastic's detection rule released on 2023-09-11 and updated on 2026-04-10.

## Attack Chain

1. **Initial Access:** An attacker compromises a GitHub user account through credential stuffing or other methods (not directly observable in this log).
2. **Privilege Escalation:** The attacker uses the compromised account to elevate the privileges of another account (possibly also compromised or newly created) to the "owner" role within the GitHub organization.
3. **Audit Log Trigger:** This action generates a GitHub audit log event, specifically an `org.update_member` event where `github.permission` is set to `admin`.
4. **Persistence:** With the elevated privileges, the attacker gains persistent access to the organization's resources, even if the original compromised account is detected and remediated.
5. **Reconnaissance:** The attacker leverages the owner role to access and review sensitive repositories, user information, and organizational settings.
6. **Data Exfiltration / Modification:** The attacker uses their elevated permissions to exfiltrate sensitive data, modify repository contents, or alter security configurations.
7. **Cover Tracks:** The attacker attempts to modify or delete audit logs to hide their activities.

## Impact

Successful exploitation allows attackers to gain complete control over the GitHub organization. This can lead to data breaches, intellectual property theft, supply chain compromise via code modification, and service disruption. The attacker can create new accounts, modify existing ones, and change security settings, potentially impacting all repositories and users within the organization. The attacker can maintain a persistent foothold and continue to compromise the organization's assets.

## Recommendation

*   Deploy the provided Sigma rule `GitHub Owner Role Granted To User` to your SIEM and tune for your environment. Enable GitHub audit logging to collect the necessary events.
*   Investigate all alerts triggered by the `GitHub Owner Role Granted To User` Sigma rule by validating the legitimacy of the role change.
*   Review and enforce multi-factor authentication (MFA) for all GitHub users, especially those with administrative privileges.
*   Implement the additional monitoring and alerting for changes to high-privilege roles within the organization to detect similar threats in the future, as recommended in the rule documentation.
