---
title: Google Workspace Admin Role Deletion
slug: 2026-06-google-workspace-admin-role-deletion
description: Adversaries with elevated privileges within Google Workspace may delete custom administrative roles to impede security operations, remove delegated administrator access, or obfuscate their activities during an active incident, leading to disrupted delegated administration, loss of security team access, or hindrance of incident response efforts.
date: "2026-06-18T15:30:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - google-workspace
  - identity-and-access-audit
  - impact
  - defense-evasion
  - admin-role-deletion
vendors:
  - Google
products:
  - Google Workspace
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
references:
  - https://support.google.com/a/answer/2406043?hl=en
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two
rules:
  - title: Detect Google Workspace Admin Role Deletion
    description: Detects when a custom administrative role is deleted in Google Workspace. Adversaries may delete a custom admin role to disrupt delegated administration, remove security team access, or hinder incident response by revoking privileges.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1484
      - T1531
    data_sources:
      - cloud
      - google_workspace
  - title: Detect Google Workspace Admin Role Unassignment
    description: Detects when an administrative role is unassigned from a user or group in Google Workspace. Adversaries may unassign security team members from roles to remove their access and hinder incident response.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1484
      - T1531
    data_sources:
      - cloud
      - google_workspace
rules_count: 2
---

Adversaries with elevated privileges within Google Workspace may delete custom administrative roles to impede security operations, remove delegated administrator access, or obfuscate their activities during an active incident. This action, often observed post-compromise, targets roles specifically configured for security teams or those granting granular access to critical services like audit logs or user management. The deletion of a custom role immediately revokes all associated privileges from assigned users and groups, potentially creating significant operational disruption and blind spots for defenders. Understanding the details of such deletions requires thorough review of historical audit logs to reconstruct the role's original permissions and assigned principals. This tactic hinders incident response capabilities and allows threat actors to maintain persistence or further their objectives undetected.

## Attack Chain

1.  **Initial Access**: An attacker gains unauthorized access to a Google Workspace administrator account, often through phishing, credential stuffing, or exploiting a vulnerable connected application.
2.  **Privilege Escalation/Maintenance**: The attacker leverages the compromised account, or further elevates privileges if necessary, to ensure sufficient permissions to modify or delete administrative roles within Google Workspace.
3.  **Reconnaissance**: The attacker enumerates existing custom administrative roles to identify those granting sensitive permissions, particularly roles held by security personnel or those with broad access to audit logs or security settings.
4.  **Defense Evasion Preparation**: The attacker plans to remove roles that could enable detection or response, such as roles held by incident responders or those that monitor critical security events.
5.  **Admin Role Deletion**: The attacker executes the deletion of one or more identified custom administrative roles via the Google Admin console or API, specifying the `google_workspace.admin.role.name`. This action triggers an `event.action: DELETE_ROLE` in audit logs.
6.  **Impact Activation**: The deletion instantly revokes all associated privileges from users and groups previously assigned to the role, leading to disrupted delegated administration, loss of security team access, or hindrance of incident response efforts.
7.  **Continued Operations**: With security monitoring or administrative oversight potentially impaired, the attacker proceeds with their primary objectives, such as data exfiltration or further system compromise, with reduced risk of detection.

## Impact

The deletion of custom administrative roles in Google Workspace can severely impact an organization's security posture and operational continuity. It directly results in the immediate revocation of privileges for all users and groups previously assigned to the deleted role, potentially disrupting delegated administration and critical security functions. This action can blind security teams to ongoing threats by removing their access to audit logs or security settings, thereby hindering incident response efforts. Organizations may experience operational downtime, increased risk of data breaches, or delayed threat containment due to compromised administrative capabilities. Understanding the full blast radius requires reviewing historical audit logs to identify all affected principals and permissions, complicating recovery.

## Recommendation

*   Enable comprehensive logging for Google Workspace administrative events, specifically ensuring `data_stream.dataset: google_workspace.admin` and `event.action: DELETE_ROLE` are collected and forwarded to your SIEM.
*   Deploy the `Detect Google Workspace Admin Role Deletion` and `Detect Google Workspace Admin Role Unassignment` Sigma rules in this brief to your SIEM and tune for your environment.
*   Upon detection of admin role deletion or unassignment, immediately investigate the `user.email` and `source.ip` of the initiating account, and the `google_workspace.admin.role.name` affected.
*   Cross-reference all role deletion/unassignment events with approved change management requests and validate the authorization of the performing administrator to distinguish between legitimate and malicious activity.
*   If an unauthorized role deletion is confirmed, prioritize recreating the affected role with equivalent privileges and reassigning previously impacted users and groups to restore critical administrative functions.
