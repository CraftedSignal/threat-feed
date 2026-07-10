---
title: Google Workspace Marketplace Restrictions Modified to Allow Any App
slug: 2024-01-gworkspace-marketplace-evasion
description: An adversary may modify Google Workspace Marketplace restrictions to allow installation of any application, potentially enabling the deployment of malicious APKs to end users within the Google Workspace environment, bypassing security restrictions.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - google_workspace
  - defense_evasion
  - cloud
vendors:
  - Google
products:
  - Google Workspace
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://support.google.com/a/answer/6089179?hl=en
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two
  - https://attack.mitre.org/techniques/T1484/
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/001/
rules:
  - title: Google Workspace Marketplace Allow-All Setting
    description: Detects when the Google Workspace Marketplace restrictions are changed to allow any application.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1484
      - T1562
    data_sources:
      - configuration
      - google_workspace
  - title: Google Workspace Marketplace App Installation
    description: Detects when a new application is added to Google Workspace after the Marketplace settings have been modified.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1484
      - T1562
    data_sources:
      - configuration
      - google_workspace
rules_count: 2
---

This rule detects when Google Marketplace restrictions within a Google Workspace environment are modified to allow the installation of any application. Such a configuration change can severely weaken the security posture of the organization, as it bypasses the intended restrictions that prevent users from installing potentially malicious applications. Adversaries could upload malicious APKs to the Google Marketplace and, by enabling the "allow any app" setting, facilitate their installation on mobile devices managed within the Google Workspace. Google clearly states that they are not responsible for any product on the Marketplace that originates from a source other than Google. This change allows any application from the marketplace to be installed and executed on mobile devices within a Google Workspace environment prior to distributing the malicious APK to the end user. This rule identifies when the global allow-all setting is enabled for Google Workspace Marketplace applications.

## Attack Chain

1.  An attacker gains administrative access to the Google Workspace environment, potentially through compromised credentials or exploiting a vulnerability in the administrative interface.
2.  The attacker navigates to the Google Workspace admin console and accesses the Google Workspace Marketplace Apps settings.
3.  The attacker modifies the "Apps Access Setting Allowlist access" setting for the Google Workspace Marketplace application.
4.  The attacker changes the setting from a restricted state (e.g., only allowing whitelisted applications) to "ALLOW_ALL".
5.  The attacker uploads a malicious APK to the Google Marketplace.
6.  Users within the Google Workspace environment are now able to install the malicious APK without restriction.
7.  The malicious APK executes on users' mobile devices, potentially leading to data theft, malware infection, or other malicious activities.
8.  The attacker leverages the compromised devices to gain further access to the Google Workspace environment or other connected systems.

## Impact

If successful, this attack can lead to widespread compromise of mobile devices within the Google Workspace environment. The number of affected users depends on the size of the organization and the number of users who install the malicious application. This can result in data breaches, financial losses, and reputational damage. The sectors targeted are broad, encompassing any organization using Google Workspace.

## Recommendation

*   Deploy the Sigma rule `Google Workspace Marketplace Allow-All Setting` to detect when the "Apps Access Setting Allowlist access" is set to `ALLOW_ALL` in Google Workspace admin logs.
*   Investigate any instances where the `google_workspace.admin.new_value` field is set to `ALLOW_ALL` for the `Google Workspace Marketplace` application, as identified by the Sigma rule `Google Workspace Marketplace Allow-All Setting`.
*   Regularly review and audit Google Workspace Marketplace app settings to ensure they align with security best practices, as mentioned in the references.
*   Implement multi-factor authentication (MFA) for all administrative accounts in Google Workspace to prevent unauthorized access, which is the initial requirement for this attack.
*   Monitor the `event.action` is `ADD_APPLICATION` to identify applications installed after these changes were made. as described in the Overview
