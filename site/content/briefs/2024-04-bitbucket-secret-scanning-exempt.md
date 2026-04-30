---
title: Bitbucket Repository Exempted from Secret Scanning
slug: 2024-04-bitbucket-secret-scanning-exempt
description: An attacker may attempt to disable or bypass secret scanning on a Bitbucket repository to avoid detection of committed secrets, potentially leading to credential compromise and subsequent unauthorized access.
date: "2024-04-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - attack.defense-impairment
  - attack.t1685
  - bitbucket
vendors:
  - Atlassian
products:
  - Bitbucket Server
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
  - https://confluence.atlassian.com/bitbucketserver/secret-scanning-1157471613.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_secret_scanning_exempt_repository_detected.yml
rules:
  - title: Bitbucket Secret Scanning Exempt Repository Added
    description: Detects when a repository is exempted from the secret scanning feature in Bitbucket.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    data_sources:
      - bitbucket
      - audit
  - title: Bitbucket Secret Scanning Configuration Modified
    description: Detects modifications to secret scanning settings, such as enabling or disabling the feature globally.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    data_sources:
      - bitbucket
      - audit
rules_count: 2
---

Attackers can weaken an organization's security posture by disabling or bypassing security controls within Bitbucket. This allows sensitive information, such as API keys, passwords, and other credentials, to be committed to the repository without detection. By adding a repository to the secret scanning exemption list, attackers can effectively disable a key preventative measure, making it easier to introduce and maintain compromised credentials within the codebase. This can lead to unauthorized access, data breaches, and other serious security incidents. This technique allows attackers to impair defenses, avoiding detection of secrets being committed to the repository.

## Attack Chain

1. An attacker gains unauthorized access to a Bitbucket account with repository administration privileges.
2. The attacker navigates to the repository settings within Bitbucket.
3. The attacker accesses the secret scanning configuration for the repository.
4. The attacker identifies the option to add the repository to the exemption list for secret scanning.
5. The attacker adds the repository to the exemption list, effectively disabling secret scanning for that repository.
6. The attacker commits sensitive information (secrets, credentials) to the now-exempt repository.
7. The secrets are committed without triggering secret scanning alerts.
8. The attacker uses the committed secrets to gain unauthorized access to other systems or data.

## Impact

Compromising secrets within a Bitbucket repository can lead to a variety of negative consequences, including unauthorized access to sensitive data, compromised infrastructure, and data breaches. While the exact number of affected organizations is unknown, the potential impact is significant for any organization using Bitbucket to store code and manage secrets. Successful exploitation allows attackers to move laterally within the network and escalate privileges.

## Recommendation

*   Deploy the Sigma rule "Bitbucket Secret Scanning Exempt Repository Added" to your SIEM to detect when a repository is added to the secret scanning exemption list (logsource: bitbucket).
*   Investigate any detected instances of repositories being added to the secret scanning exemption list to determine if the change was authorized.
*   Ensure that appropriate access controls are in place to prevent unauthorized users from modifying repository settings.
*   Review Bitbucket audit logs regularly to identify suspicious activity related to secret scanning configuration changes (logsource: bitbucket).
