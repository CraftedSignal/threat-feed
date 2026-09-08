---
title: AWS Root Console Password Spraying Campaign
slug: 2026-09-aws-root-spraying
description: Threat actors are performing password spraying against AWS root accounts by distributing authentication attempts across multiple AWS accounts from a single source IP to evade lockout mechanisms.
date: "2026-09-08T07:31:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - cloud
  - identity
  - aws
vendors:
  - Amazon
products:
  - AWS Management Console
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: Password spraying is a credential access technique where an attacker tries a small number of commonly used or leaked passwords across many accounts.
    confidence_band: high
references:
  - https://securitylabs.datadoghq.com/articles/aws-root-user-bruteforce-campaign/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/credential_access_root_console_password_spraying.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Implement cross-account cardinality detection for failed root logins.
      owner: Detection Engineering
      due: 72h
      evidence: Source provides specific logic for AWS Organizations-level monitoring.
  mitigation_plan:
    - priority: immediate
      action: Enable multi-factor authentication (MFA) on all AWS root accounts.
      owner: IT Operations
      addresses: Root account compromise
      evidence: AWS root user best practices
---

Threat actors are actively utilizing password spraying techniques to compromise AWS root accounts. Unlike traditional brute-force attacks that focus on a single account, this campaign employs a low-volume strategy, attempting a limited number of common passwords across a wide array of AWS accounts. This methodology is specifically designed to circumvent per-account lockout policies and traditional high-volume authentication monitoring. 

The attacks originate from single source IPs, which are often routed through proxy or residential IP infrastructure to further obfuscate the source. Defenders are advised that successful authentication in this context is a critical security event that frequently precedes persistence-building activities, such as the creation of unauthorized IAM users, the generation of new access keys, or the modification of CloudTrail logging configurations. Effective detection requires visibility at the AWS Organizations level, aggregating events from all member accounts to identify the cross-account breadth of the spray.

## Impact

Successful compromise of an AWS root account provides an attacker with unrestricted access to the AWS environment. Observed damage includes the deployment of unauthorized IAM users and access keys for persistent access, as well as the potential tampering with security audit logs to hide follow-on malicious activity. Organizations targeted by this spray campaign risk significant data exfiltration, service disruption, and long-term environment backdooring if the root identity is not immediately secured.

## Recommendation

* Enable and configure an AWS Organizations-level CloudTrail trail that aggregates management events from all member accounts.
* Implement cross-account cardinality monitoring for failed root ConsoleLogin events to detect low-volume password spraying.
* Enforce hardware-based Multi-Factor Authentication (MFA) on all root accounts to neutralize the impact of compromised passwords.
* Establish automated alerting for high-risk IAM operations (e.g., CreateAccessKey, AttachRolePolicy) immediately following a successful root login.
* Review CloudTrail logs for outdated or suspicious User-Agent strings often associated with automated spray tooling.
