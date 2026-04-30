---
title: Bitbucket Global Secret Scanning Rule Deletion
slug: 2024-04-bitbucket-secret-rule-delete
description: An adversary with administrative privileges may delete global secret scanning rules in Bitbucket to impair defenses and exfiltrate sensitive data without detection.
date: "2024-04-29T14:00:00Z"
type: advisory
types:
  - advisory
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
  - https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_global_secret_scanning_rule_deleted.yml
rules:
  - title: Bitbucket Global Secret Scanning Rule Deleted
    description: Detects Bitbucket global secret scanning rule deletion activity.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    data_sources:
      - bitbucket
      - audit
  - title: Bitbucket Failed Login followed by Secret Rule Deletion
    description: Detects a failed login attempt followed by secret rule deletion, indicating potential credential compromise.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
      - initial_access
    techniques:
      - T1110
    data_sources:
      - bitbucket
      - audit
rules_count: 2
---

This threat brief addresses the deletion of global secret scanning rules within Bitbucket environments. Secret scanning is a crucial defense mechanism used to prevent sensitive information, such as API keys and passwords, from being committed to repositories. An attacker with global administration privileges could intentionally delete these rules to bypass security controls. This action could occur post-compromise, as part of an insider threat, or due to accidental misconfiguration. The impact of this activity centers around an increased risk of sensitive data exposure, which can lead to further compromise or data breaches. Defenders should monitor Bitbucket audit logs for such deletions.

## Attack Chain

1.  The attacker gains valid credentials with global administrator privileges within the Bitbucket environment, possibly through credential stuffing or phishing.
2.  The attacker authenticates to the Bitbucket web interface or uses the Bitbucket API with their compromised credentials.
3.  The attacker navigates to the global secret scanning rule configuration page.
4.  The attacker identifies and selects one or more global secret scanning rules currently in effect.
5.  The attacker initiates the deletion process for the selected rules, confirming the action when prompted.
6.  Bitbucket processes the deletion request, removing the rules from the global configuration.
7.  The system generates an audit log event indicating the deletion of the global secret scanning rule.
8.  With secret scanning disabled, developers may inadvertently commit secrets into Bitbucket repositories, making them available to the attacker.

## Impact

Successful deletion of global secret scanning rules can have significant impact. Without active secret scanning, developers may unintentionally commit sensitive information (API keys, passwords, tokens) into Bitbucket repositories. This could lead to account takeovers, data breaches, or lateral movement within the organization's infrastructure. The number of affected repositories and exposed secrets will vary depending on the scope of the attacker's access and the activity of developers during the period when the rules were disabled.

## Recommendation

*   Deploy the provided Sigma rule to detect the deletion of global secret scanning rules in Bitbucket audit logs, focusing on `auditType.category: 'Global administration'` and `auditType.action: 'Global secret scanning rule deleted'` (Sigma rule).
*   Investigate any detected instances of global secret scanning rule deletion to determine if the action was authorized and performed by a legitimate user.
*   Implement multi-factor authentication (MFA) for all Bitbucket accounts, especially those with administrative privileges, to reduce the risk of credential compromise.
*   Regularly review Bitbucket user permissions and roles to ensure that users have only the necessary level of access.
*   Enable "Basic" logging level, as required, to ensure the necessary audit events are generated (logsource definition).
