---
title: GitHub Security Feature Disablement
slug: 2024-11-github-security-disabled
description: An administrator or privileged user disables critical security features within a GitHub organization or repository, potentially leading to increased risk of unauthorized access, data breaches, and persistent compromise.
date: "2024-10-31T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - github
  - security-configuration
  - defense-evasion
vendors:
  - GitHub
products:
  - GitHub
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/disabling-oauth-app-access-restrictions-for-your-organization
  - https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization#dependabot_alerts-category-actions
  - https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-security-and-analysis-settings-for-your-repository
  - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise
rules:
  - title: GitHub Disable Two Factor Requirement
    description: Detects when a user disables the two-factor authentication requirement for a GitHub organization.
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - defense-impairment
      - persistence
    techniques:
      - T1556
    data_sources:
      - github
      - audit
  - title: GitHub Disable Advanced Security Feature
    description: Detects when a user disables advanced security features for an organization or repository.
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - defense-impairment
      - persistence
    techniques:
      - T1556
    data_sources:
      - github
      - audit
  - title: GitHub Disable OAuth App Restrictions
    description: Detects when a user disables OAuth application restrictions for a GitHub organization.
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - defense-impairment
      - persistence
    techniques:
      - T1556
    data_sources:
      - github
      - audit
rules_count: 3
---

This brief addresses the threat of unauthorized or malicious disabling of security features within GitHub organizations and repositories. Attackers or malicious insiders might disable features like Advanced Security, OAuth application restrictions, or two-factor authentication to weaken the security posture, gain unauthorized access, and establish persistence. The affected features span across advanced security, OAuth application management, and two-factor authentication enforcement. These actions can be performed by users with administrative or owner privileges within the GitHub organization. Defenders need to monitor for these configuration changes to ensure security best practices are maintained and to quickly identify potential malicious activity.

## Attack Chain

1.  An attacker gains unauthorized access to a GitHub account with organization owner or administrator privileges through compromised credentials or insider access.
2.  The attacker authenticates to the GitHub organization or repository using the compromised account.
3.  The attacker navigates to the organization settings or repository settings, depending on the scope of the targeted security feature.
4.  The attacker disables advanced security features (e.g., `business_advanced_security.disabled_for_new_repos`, `repo.advanced_security_disabled`) through the GitHub web interface or API.
5.  Alternatively, the attacker disables OAuth application restrictions (`org.disable_oauth_app_restrictions`) to allow potentially malicious applications to access organizational data.
6.  Or, the attacker disables the two-factor authentication requirement (`org.disable_two_factor_requirement`) for the organization, weakening account security.
7.  The attacker may then proceed to exploit the weakened security posture to access sensitive repositories, modify code, or exfiltrate data.
8.  The attacker establishes persistent access by creating rogue OAuth applications or adding unauthorized users to the organization.

## Impact

Disabling security features in GitHub can lead to severe consequences. A successful attack can result in unauthorized access to sensitive code repositories, intellectual property theft, and data breaches. Disabling two-factor authentication makes accounts more vulnerable to credential stuffing and phishing attacks. The scope can range from a single repository to an entire organization, impacting hundreds or thousands of users and projects. The financial and reputational damage to the organization can be significant.

## Recommendation

*   Deploy the Sigma rule `Github High Risk Configuration Disabled` to detect the disabling of critical security features by monitoring GitHub audit logs.
*   Enable audit log streaming as documented in the rule definition to ensure that the necessary logs are captured for detection.
*   Investigate any detected instances of security feature disabling to determine if they are legitimate administrator actions or malicious activity.
*   Enforce multi-factor authentication (MFA) for all users, especially those with administrative privileges, and monitor for attempts to disable MFA.
*   Regularly review and validate GitHub organization and repository settings to ensure that security features are enabled and configured correctly.
