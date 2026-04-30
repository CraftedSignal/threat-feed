---
title: AWS Identity Center Identity Provider Modification
slug: 2024-01-03-aws-idp-change
description: An adversary modifies the AWS Identity Center identity provider configuration, potentially leading to persistent access and privilege escalation through user impersonation.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - identity
  - persistence
  - credential-access
  - defense-evasion
vendors:
  - Amazon
products:
  - AWS Identity Center
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://docs.aws.amazon.com/singlesignon/latest/userguide/app-enablement.html
  - https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html
  - https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiamidentitycentersuccessortoawssinglesign-on.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_sso_idp_change.yml
rules:
  - title: AWS Identity Center Identity Provider Change
    description: Detects a change in the AWS Identity Center (FKA AWS SSO) identity provider, which could indicate malicious activity.
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - defense-impairment
      - persistence
    techniques:
      - T1556
    data_sources:
      - aws
      - cloudtrail
  - title: AWS SSO Directory Disassociation
    description: Detects the disassociation of a directory from AWS SSO, which may precede malicious reassociation.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
      - persistence
    techniques:
      - T1556
    data_sources:
      - aws
      - cloudtrail
rules_count: 2
---

AWS Identity Center (formerly AWS SSO) enables centralized management of access to AWS accounts and applications. Attackers can manipulate the configured identity provider to gain unauthorized access. The modification of the configured Identity Provider (IdP) within AWS Identity Center can lead to a full compromise of the AWS environment. By associating a malicious directory or disabling/disassociating legitimate directories, attackers can potentially establish persistent access, escalate privileges, and impersonate legitimate users. This can be achieved by utilizing compromised AWS credentials or exploiting vulnerabilities in the AWS environment.

## Attack Chain

1. Initial access is gained via compromised AWS credentials or by exploiting an AWS vulnerability.
2. The attacker enumerates the current AWS Identity Center configuration to identify the currently associated directory.
3. The attacker disassociates the existing, legitimate directory using `DisassociateDirectory`.
4. The attacker associates a malicious directory they control using `AssociateDirectory`. This malicious directory is configured to impersonate legitimate users.
5. Alternatively, the attacker disables external IdP configuration for the directory using `DisableExternalIdPConfigurationForDirectory`.
6. The attacker enables external IdP configuration for the directory, pointing to an attacker-controlled IdP, using `EnableExternalIdPConfigurationForDirectory`.
7. The attacker uses the malicious or attacker-controlled IdP to authenticate as legitimate users, gaining access to AWS resources.
8. The attacker performs malicious actions within the AWS environment, such as data exfiltration or resource destruction.

## Impact

Successful modification of the AWS Identity Center identity provider can lead to complete compromise of an AWS environment. Attackers can gain persistent access, escalate privileges, and impersonate legitimate users. This can result in data breaches, service disruption, financial loss, and reputational damage. The impact can extend to all AWS accounts and applications managed by the compromised Identity Center instance.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect unauthorized changes to the AWS Identity Center identity provider.
*   Investigate any detected events related to `AssociateDirectory`, `DisableExternalIdPConfigurationForDirectory`, `DisassociateDirectory`, or `EnableExternalIdPConfigurationForDirectory` in AWS CloudTrail logs.
*   Implement multi-factor authentication (MFA) for all AWS accounts and users to reduce the risk of credential compromise.
*   Review and restrict IAM permissions to minimize the blast radius of compromised credentials.
*   Monitor AWS CloudTrail logs for unusual activity patterns that might indicate malicious directory association attempts.
