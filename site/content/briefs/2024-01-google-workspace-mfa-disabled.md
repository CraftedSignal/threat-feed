---
title: Google Workspace MFA Enforcement Disabled
slug: 2024-01-google-workspace-mfa-disabled
description: Detection of multi-factor authentication (MFA) enforcement being disabled for Google Workspace users, potentially weakening security controls and leading to account compromise.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - google-workspace
  - mfa
  - account-compromise
vendors:
  - Google
products:
  - Google Workspace
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://support.google.com/a/answer/9176657?hl=en#
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two
rules:
  - title: Google Workspace MFA Enforcement Disabled
    description: Detects when multi-factor authentication (MFA) enforcement is disabled for Google Workspace users.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
      - impact
    techniques:
      - T1531
      - T1556.006
      - T1556.006
    data_sources:
      - webserver
      - linux
  - title: Google Workspace MFA Enforcement Disabled - Event Logs
    description: Detects when multi-factor authentication (MFA) enforcement is disabled for Google Workspace users based on event logs.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
      - impact
    techniques:
      - T1531
      - T1556.006
      - T1556.006
    data_sources:
      - event
      - google_workspace
rules_count: 2
---

The disabling of multi-factor authentication (MFA) enforcement in Google Workspace can severely weaken an organization's security posture. Attackers may target MFA settings to gain unauthorized access to user accounts and sensitive data. This activity, often performed by compromised administrative accounts, allows attackers to bypass an important control mechanism designed to protect user identities. Google Workspace administrators should closely monitor changes to MFA enforcement policies, as these changes can expose the organization to significant risk. The default Filebeat module polls Google's reporting API every 2 hours, but the Google documentation states there can be lag times ranging from minutes up to 3 days between an event occurrence and its visibility in the admin/audit logs. Reducing this interval can help reduce false negatives.

## Attack Chain

1. An attacker compromises a Google Workspace administrator account, potentially through phishing or credential stuffing.
2. The attacker authenticates to the Google Workspace admin console using the compromised credentials.
3. The attacker navigates to the MFA settings within the Google Workspace admin console.
4. The attacker modifies the MFA enforcement policy, disabling MFA for specific users or the entire organization.
5. The attacker attempts to log in to target user accounts without being prompted for a second factor.
6. The attacker gains access to sensitive data and resources within Google Workspace, such as email, documents, and applications.
7. The attacker may move laterally to other systems or cloud services using the compromised user accounts.

## Impact

Disabling MFA enforcement exposes Google Workspace accounts to unauthorized access, potentially impacting all users within the organization. This can lead to data breaches, financial losses, and reputational damage. Depending on the compromised accounts, attackers can access and exfiltrate sensitive information, disrupt business operations, and launch further attacks against the organization and its customers.

## Recommendation

*   Deploy the Sigma rule `Google Workspace MFA Enforcement Disabled` to your SIEM to detect when MFA enforcement is disabled.
*   Enable Google Workspace Fleet integration, Filebeat module, or similar data ingestion pipeline to collect the necessary logs for the Sigma rule.
*   Investigate any detected instances of MFA being disabled, as this could indicate a compromised administrator account.
*   Review the permissions assigned to the implicated user to ensure that the least privilege principle is being followed.
*   Implement security best practices outlined by Google.
