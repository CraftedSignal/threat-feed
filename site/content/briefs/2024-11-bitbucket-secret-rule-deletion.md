---
title: Bitbucket Secret Scanning Rule Deleted
slug: 2024-11-bitbucket-secret-rule-deletion
description: Attackers may delete secret scanning rules in Bitbucket to impair defenses and introduce secrets into the code repository undetected, potentially leading to unauthorized access or data breaches.
date: "2024-11-17T14:22:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - attack.defense-impairment
  - attack.t1685
vendors:
  - Atlassian
products:
  - Bitbucket
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
  - https://confluence.atlassian.com/bitbucketserver/secret-scanning-1157471613.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_secret_scanning_rule_deleted.yml
rules:
  - title: Bitbucket Secret Scanning Rule Deleted
    description: Detects when a secret scanning rule is deleted for the project or repository in Bitbucket audit logs.
    platform: sigma
    severity: low
    tactics:
      - defense-impairment
    data_sources:
      - bitbucket
      - audit
  - title: Bitbucket Failed Login Attempt
    description: Detects failed login attempts to Bitbucket, which can indicate brute-force attacks or account compromise attempts.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1110
    data_sources:
      - bitbucket
      - audit
rules_count: 2
---

Attackers with sufficient privileges within a Bitbucket project or repository may delete secret scanning rules. These rules are designed to automatically detect and prevent the committing of sensitive information like API keys, passwords, and tokens directly into the codebase. By removing these rules, adversaries can bypass security controls and introduce secrets into the repository undetected. This could be a precursor to a larger attack, where the leaked secrets are used to gain unauthorized access to systems, data, or other resources. This activity may occur as a part of a broader insider threat campaign or an external attacker who has gained control of a privileged account.

## Attack Chain

1.  The attacker compromises a Bitbucket account with project or repository administrator privileges.
2.  The attacker authenticates to the Bitbucket web interface or uses the Bitbucket API with the compromised account.
3.  The attacker navigates to the project or repository settings where secret scanning rules are configured.
4.  The attacker identifies the secret scanning rules in place.
5.  The attacker initiates the deletion of one or more secret scanning rules through the Bitbucket web interface or API.
6.  Bitbucket processes the request and removes the specified secret scanning rules.
7.  The attacker (or another compromised account) commits code containing secrets, which are no longer detected due to the deleted rules.
8.  The committed secrets are then potentially used for lateral movement, data exfiltration, or other malicious activities.

## Impact

The deletion of secret scanning rules in Bitbucket can lead to the undetected introduction of sensitive information into the codebase. This can result in unauthorized access to systems, data breaches, and other security incidents. The impact can range from minor data exposure to significant financial losses and reputational damage, depending on the scope and sensitivity of the leaked secrets. Organizations relying on Bitbucket for source code management are vulnerable.

## Recommendation

*   Monitor Bitbucket audit logs for events related to secret scanning rule deletions, using the provided Sigma rule to detect suspicious activity (`bitbucket_audit_secret_scanning_rule_deleted.yml`).
*   Implement multi-factor authentication (MFA) for all Bitbucket accounts, especially those with administrative privileges, to reduce the risk of account compromise.
*   Enforce the principle of least privilege, ensuring that users only have the necessary permissions to perform their tasks.
*   Regularly review and audit Bitbucket user permissions and access controls.
*   Implement strong password policies and encourage users to use unique, complex passwords.
