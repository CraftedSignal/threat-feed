---
title: Bitbucket Project Secret Scanning Allowlist Added
slug: 2024-04-bitbucket-secret-scanning-allowlist
description: An adversary may impair defenses by adding a secret scanning allowlist rule for Bitbucket projects, potentially allowing secrets to be committed and exposed.
date: "2024-04-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - attack.defense-impairment
  - attack.t1685
vendors:
  - Atlassian
products:
  - Bitbucket
references:
  - https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
  - https://confluence.atlassian.com/bitbucketserver/secret-scanning-1157471613.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_project_secret_scanning_allowlist_added.yml
rules:
  - title: Bitbucket Project Secret Scanning Allowlist Added
    description: Detects when a secret scanning allowlist rule is added for projects.
    platform: sigma
    severity: low
    tactics:
      - defense-impairment
    data_sources:
      - bitbucket
      - audit
  - title: Bitbucket Project Settings Accessed
    description: Detects when a user accesses project settings in Bitbucket, which may precede malicious configuration changes.
    platform: sigma
    severity: informational
    tactics:
      - defense-evasion
    techniques:
      - T1562
    data_sources:
      - bitbucket
      - audit
rules_count: 2
---

The addition of a secret scanning allowlist rule to a Bitbucket project can be abused by malicious actors to bypass security controls. While not inherently malicious, this action can be exploited to weaken an organization's security posture. Secret scanning tools are designed to prevent the accidental or intentional commit of sensitive information (API keys, passwords, etc.) into version control systems. By adding an allowlist rule, specific patterns or files can be excluded from these scans. This could be leveraged by an attacker who has gained access to a Bitbucket account or project to intentionally introduce secrets while avoiding detection. The activity is logged by Bitbucket's audit logs, providing an opportunity for detection.

## Attack Chain

1.  The attacker gains unauthorized access to a Bitbucket account with sufficient privileges to modify project settings.
2.  The attacker navigates to the project settings within Bitbucket.
3.  The attacker accesses the secret scanning configuration for the project.
4.  The attacker adds a new allowlist rule, specifying a pattern or file to be excluded from secret scanning.
5.  The attacker commits code containing secrets that match the allowlist rule, effectively bypassing the secret scanning tool.
6.  The changes are pushed to the Bitbucket repository.
7.  The secrets remain undetected due to the allowlist rule.
8.  The attacker leverages the exposed secrets for further malicious activities, such as gaining access to other systems or data.

## Impact

Successful exploitation could lead to the exposure of sensitive information such as API keys, passwords, or other credentials. This can result in unauthorized access to internal systems, data breaches, and reputational damage. The number of affected projects depends on the scope of the attacker's access and the configuration of the allowlist rule. The addition of the allowlist rule itself does not directly cause damage but creates a window of opportunity for the introduction and persistence of secrets within the codebase.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect the addition of secret scanning allowlist rules (logsource: bitbucket, service: audit).
*   Investigate any detected instances of allowlist rule additions to verify their legitimacy and business justification.
*   Review and enforce strict access controls for Bitbucket projects to minimize the risk of unauthorized modifications.
*   Enable "Basic" log level in Bitbucket to ensure that the audit events required for detection are captured, as indicated in the rule definition.
