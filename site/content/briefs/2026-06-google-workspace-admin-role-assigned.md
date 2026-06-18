---
title: Google Workspace Admin Role Assigned to a User or Group
slug: 2026-06-google-workspace-admin-role-assigned
description: Adversaries leverage the assignment of administrative roles within Google Workspace to an existing or new user/group, establishing persistence and escalating privileges to gain broad control over the tenant, including bypassing single sign-on.
date: "2026-06-18T15:31:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud-security
  - google-workspace
  - persistence
  - privilege-escalation
  - account-manipulation
  - saas-security
vendors:
  - Google
products:
  - Google Workspace
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
  - https://support.google.com/a/answer/172176?hl=en
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two
  - https://support.google.com/a/answer/7587183
  - https://support.google.com/a/answer/7061566
  - https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-google_workspace.html
rules:
  - title: Google Workspace Admin Role Assigned to User or Group
    description: Detects when any administrative role (ending in _ADMIN_ROLE) is assigned to a user or group in Google Workspace, indicating potential persistence or privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
      - T1098.003
    data_sources:
      - saas
      - google_workspace
  - title: Google Workspace Super Admin Role Assignment
    description: Detects the assignment of the highly privileged SUPER_ADMIN_ROLE to a user or group in Google Workspace, which can provide complete control over the tenant.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
      - T1098.003
    data_sources:
      - saas
      - google_workspace
rules_count: 2
---

Adversaries are known to target cloud environments like Google Workspace to establish persistent access and escalate privileges. A critical technique involves assigning administrative roles, such as the `SUPER_ADMIN_ROLE` or other `*_ADMIN_ROLE` types, to existing or newly created user accounts or groups. This action, often occurring post-initial compromise, grants attackers broad control over the Google Workspace tenant, including the ability to manage users, devices, security settings, and applications. Such elevated privileges enable adversaries to bypass security mechanisms like Single Sign-On (SSO), ensure long-term presence, and facilitate follow-on activities like data exfiltration, modifying mail routing, or altering other critical configurations, posing a significant risk to organizational data and operations.

## Attack Chain

1.  **Initial Compromise**: Adversary obtains initial access to a Google Workspace account, potentially an administrator account or an account with privileges to create users or manage groups.
2.  **Privilege Discovery**: The adversary identifies existing user accounts or creates new ones that can be granted elevated administrative roles within Google Workspace.
3.  **Role Assignment**: The adversary assigns a high-privilege administrative role (e.g., `SUPER_ADMIN_ROLE`, `GROUP_ADMIN_ROLE`) to a compromised or newly created user account or an existing group.
4.  **Persistence Establishment**: The elevated role provides the adversary with sustained access to the Google Workspace environment, often bypassing standard security controls like Single Sign-On (SSO).
5.  **Further Actions**: Utilizing the newly acquired administrative privileges, the adversary performs additional malicious activities, such as creating OAuth tokens, modifying security controls, changing mail routing, or altering SSO settings.
6.  **Data Exfiltration/Impact**: The adversary may then proceed with data exfiltration, service disruption, or other objectives, maintaining broad control over the tenant's identity, device, and application settings.

## Impact

The successful assignment of administrative roles to an adversary-controlled account grants comprehensive control over the affected Google Workspace tenant. This can lead to unauthorized access to sensitive organizational data, alteration of critical security controls (such as SSO settings), disruption of email communications, and creation of backdoors (e.g., OAuth tokens) for sustained access. Organizations across all sectors are vulnerable, and the impact can range from severe data breaches and compliance failures to operational paralysis and reputational damage.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment, specifically focusing on `google_workspace.admin.role.name` values.
*   Ensure Google Workspace Admin logs are being ingested into your security monitoring platform to enable detection of `event.action: "ASSIGN_ROLE"` events.
*   Regularly audit existing administrative role assignments within Google Workspace, paying close attention to `*_ADMIN_ROLE` types.
*   Implement security best practices outlined by Google, available at `https://support.google.com/a/answer/7587183`.
*   Investigate `user.email` and `source.ip` for any user performing `ASSIGN_ROLE` actions that appear unusual.
