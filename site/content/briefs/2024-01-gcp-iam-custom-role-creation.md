---
title: GCP IAM Custom Role Creation
slug: 2024-01-gcp-iam-custom-role-creation
description: Detection of Identity and Access Management (IAM) custom role creation in Google Cloud Platform (GCP), which can indicate potential privilege escalation or persistence by adversaries creating roles with excessive permissions.
date: "2024-01-02T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - gcp
  - iam
  - custom-role
  - initial-access
  - persistence
  - privilege-escalation
vendors:
  - Google
products:
  - Google Cloud Platform
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://cloud.google.com/iam/docs/understanding-custom-roles
rules:
  - title: GCP IAM Custom Role Creation
    description: Detects the creation of IAM custom roles in GCP, which may indicate potential privilege escalation or persistence.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
      - privilege_escalation
    techniques:
      - T1078
      - T1098
      - T1098.003
    data_sources:
      - cloudtrail
      - gcp
      - gcp.audit
  - title: GCP IAM Custom Role with Wildcard Permissions
    description: Detects the creation of IAM custom roles that include wildcard permissions, which are overly permissive and should be avoided.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
      - privilege_escalation
    techniques:
      - T1078
      - T1098
      - T1098.003
    data_sources:
      - cloudtrail
      - gcp
      - gcp.audit
  - title: GCP IAM Custom Role Creation by Uncommon Identity
    description: Detects IAM custom role creation from unusual users or service accounts, potentially indicating compromised accounts or malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
      - privilege_escalation
    techniques:
      - T1078
      - T1098
      - T1098.003
    data_sources:
      - cloudtrail
      - gcp
      - gcp.audit
rules_count: 3
---

This threat brief focuses on the detection of IAM custom role creation within Google Cloud Platform (GCP). IAM custom roles are user-defined roles that bundle one or more supported permissions, allowing for tailored access management. While legitimate use cases exist, adversaries can exploit this feature by creating roles with excessive permissions, potentially leading to privilege escalation or persistence. This activity can be used to maintain unauthorized access and control within the GCP environment. Defenders should monitor for anomalous role creation activity, especially roles with broad or unusual permission sets, as these could signal malicious intent. The rule is designed to work with GCP Fleet integration, Filebeat module, or similarly structured data.

## Attack Chain

1. An attacker gains initial access to a GCP account, possibly through compromised credentials or exploiting a vulnerability.
2. The attacker authenticates to the GCP environment using valid credentials (T1078).
3. The attacker explores existing IAM roles and permissions to identify potential escalation paths.
4. The attacker crafts a custom IAM role with overly permissive privileges (T1098, T1098.003), granting themselves access to critical resources.
5. The attacker creates the custom IAM role using the `google.iam.admin.v*.CreateRole` API call.
6. The event is logged as a successful operation (`event.outcome:success`) in the GCP audit logs.
7. The attacker assigns the newly created custom role to a compromised or attacker-controlled user or service account.
8. The attacker leverages the escalated privileges to access sensitive data, modify configurations, or deploy malicious workloads, achieving persistence or further compromising the environment.

## Impact

Successful exploitation can lead to significant damage, including unauthorized access to sensitive data, compromised systems, and potential data exfiltration. The creation of custom roles with excessive permissions can enable adversaries to maintain persistent access to the GCP environment, escalate privileges, and bypass existing security controls. Organizations may experience data breaches, financial losses, and reputational damage.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM to detect suspicious IAM custom role creation events in GCP (logsource: gcp.audit).
*   Review and audit existing IAM roles and permissions regularly to identify and remediate overly permissive configurations.
*   Implement the principle of least privilege when assigning permissions to IAM roles, both built-in and custom.
*   Monitor GCP audit logs for `google.iam.admin.v*.CreateRole` events and investigate any unexpected or unauthorized role creation activity.
*   Ensure that only authorized personnel have the necessary permissions to create custom IAM roles, and implement controls to prevent unauthorized role creation.
*   Establish a baseline of expected role creation activity and investigate any deviations from this baseline.
