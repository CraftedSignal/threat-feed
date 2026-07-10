---
title: GitHub Organizations 2FA Requirement Disabled
slug: 2024-01-03-github-disable-2fa
description: Detection of GitHub Organizations where the two-factor authentication (2FA) requirement has been disabled, potentially indicating an attempt to weaken security controls and increase the risk of account compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - github
  - cloud
  - 2fa
  - defense-evasion
vendors:
  - GitHub
products:
  - GitHub Organizations
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://splunk.github.io/splunk-add-on-for-github-audit-log-monitoring/Install/
  - https://www.googlecloudcommunity.com/gc/Community-Blog/Monitoring-for-Suspicious-GitHub-Activity-with-Google-Security/ba-p/763610
rules:
  - title: GitHub Organizations Disable 2FA Requirement
    description: Detects when the two-factor authentication (2FA) requirement is disabled in GitHub Organizations.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1195
      - T1562.001
    data_sources:
      - cloud
      - github
  - title: GitHub Organizations 2FA Disabled by Bot Account
    description: Detects when a bot account disables the two-factor authentication (2FA) requirement in GitHub Organizations, which is highly unusual.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1195
      - T1562.001
    data_sources:
      - cloud
      - github
rules_count: 2
---

This brief focuses on the detection of disabled two-factor authentication (2FA) requirements within GitHub Organizations. The activity is detected by monitoring GitHub Organizations audit logs for the `org.disable_two_factor_requirement` event. Identifying disabled 2FA is critical because it undermines a fundamental security control and can expose organizations to increased risk of account takeover. The absence of 2FA makes accounts more vulnerable to password-based attacks, potentially granting attackers access to sensitive code, intellectual property, and the ability to compromise the software supply chain. This event can be an early warning sign of a more extensive attack campaign.

## Attack Chain

1.  The attacker gains initial access to an account with sufficient privileges to modify organization settings (T1195).
2.  The attacker authenticates to the GitHub platform, bypassing existing 2FA if the account is already enrolled.
3.  The attacker navigates to the organization settings within GitHub.
4.  The attacker disables the 2FA requirement for the GitHub organization. This action is logged as `org.disable_two_factor_requirement` in the audit logs.
5.  With 2FA disabled, the attacker targets other organization member accounts with password-based attacks such as credential stuffing or brute-force attacks.
6.  Successful account compromise allows the attacker to access private repositories and sensitive information.
7.  The attacker may inject malicious code into repositories to compromise the software supply chain.
8.  The attacker may exfiltrate sensitive data or intellectual property (T1562.001).

## Impact

The impact of disabled 2FA in GitHub Organizations can be significant, leading to account compromise, unauthorized access to sensitive code repositories, intellectual property theft, and potential compromise of the software supply chain. A successful attack could result in financial losses, reputational damage, and legal liabilities. The number of affected accounts and the severity of the impact depend on the attacker's objectives and the organization's security posture.

## Recommendation

*   Deploy the Sigma rule `GitHub Organizations Disable 2FA Requirement` to your SIEM to detect instances of 2FA being disabled (see `rules`).
*   Investigate any detected instances of disabled 2FA to determine the legitimacy of the action and identify any potential compromise.
*   Review GitHub organization audit logs for related suspicious activities, such as unusual login attempts or changes to other security settings.
*   Enforce 2FA for all members of GitHub Organizations and regularly audit 2FA enforcement policies.
*   Monitor the `github_organizations` data source for other vendor actions to identify suspicious activity within the GitHub environment.
