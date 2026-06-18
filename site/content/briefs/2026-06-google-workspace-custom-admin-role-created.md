---
title: Google Workspace Custom Admin Role Created for Persistence
slug: 2026-06-google-workspace-custom-admin-role-created
description: Adversaries may create custom administrative roles in Google Workspace to establish persistence with tailored, elevated permissions, which are then assigned to compromised or attacker-controlled accounts to bypass security controls, grant OAuth access, or modify mail routing.
date: "2026-06-18T15:32:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - google-workspace
  - cloud-security
  - persistence
  - privilege-escalation
  - iam
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
  - https://support.google.com/a/answer/2406043?hl=en
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two
rules:
  - title: Google Workspace Custom Admin Role Created
    description: Detects when a custom administrative role is created in Google Workspace, which adversaries may use to establish persistence and tailor elevated permissions.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - cloud
      - google_workspace
rules_count: 1
---

Adversaries targeting Google Workspace environments may create custom administrative roles to establish a persistent foothold and achieve granular, elevated privileges. Unlike predefined admin roles, custom roles allow threat actors to craft permissions precisely tailored to their objectives, such as modifying security controls, granting illicit OAuth access, or altering mail routing. This technique enables attackers to maintain access and perform follow-on actions even if initial access vectors are remediated or the original compromised account is secured. The creation of such a role, often followed by assigning it to a compromised or attacker-controlled account, provides a stealthy persistence mechanism that avoids alerting on modifications to well-known prebuilt roles. This activity, observed in various cloud environments, highlights the need for continuous monitoring of IAM changes.

## Attack Chain

1.  An attacker gains unauthorized access to a Google Workspace administrator account, typically through phishing, credential compromise, or exploitation of vulnerabilities.
2.  The attacker logs into the Google Workspace Admin Console using the compromised administrative credentials, assuming the identity of a legitimate administrator.
3.  Within the Admin Console, the attacker navigates to the 'Admin roles' section to initiate the creation of a new custom administrative role.
4.  The attacker defines specific, granular privileges for the new custom role, carefully selecting permissions that align with their objectives (e.g., user management, security settings, Gmail routing).
5.  To establish persistence, the attacker assigns this newly created custom role to a pre-existing compromised user account or a newly provisioned attacker-controlled account, granting it the defined permissions.
6.  With the custom role assigned, the attacker can now leverage its tailored permissions to maintain access, bypass security controls, modify system configurations, or exfiltrate data, even if the initial administrator account's access is revoked.

## Impact

Successful exploitation of this technique grants adversaries persistent and tailored access to the Google Workspace environment, enabling them to bypass existing security controls and perform various malicious activities. Attackers can modify critical security settings, grant unauthorized OAuth access to third-party applications, alter mail routing rules for data exfiltration or interception, or manipulate user accounts. The granular nature of custom roles makes detection challenging, potentially leading to prolonged undetected access, significant data breaches, and compromise of the organization's communication and collaboration infrastructure.

## Recommendation

*   Deploy the Sigma rule "Google Workspace Custom Admin Role Created" in this brief to your SIEM and tune for your environment.
*   Configure Google Workspace logging to capture `CREATE_ROLE` and `ASSIGN_ROLE` events to ensure visibility into administrative changes.
*   Review Google Workspace admin logs for `event.action: ASSIGN_ROLE` actions following a detected `CREATE_ROLE` event to identify principals receiving the new role.
*   Reduce the `var.interval` of the Google Workspace Filebeat module to 10 minutes (from the default 2 hours) to minimize event lag as described in the Setup section.
