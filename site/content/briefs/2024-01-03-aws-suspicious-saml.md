---
title: Suspicious AWS SAML Activity Detection
slug: 2024-01-03-aws-suspicious-saml
description: This rule identifies suspicious SAML activity in AWS, such as AssumeRoleWithSAML and UpdateSAMLProvider events, which could indicate an attacker gaining backdoor access, escalating privileges, or establishing persistence.
date: "2024-01-03T18:22:30Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - aws
  - saml
  - cloudtrail
  - initial-access
  - lateral-movement
  - persistence
  - privilege-escalation
  - stealth
vendors:
  - Amazon
products:
  - AWS IAM
  - AWS STS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateSAMLProvider.html
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_susp_saml_activity.yml
rules:
  - title: AWS AssumeRoleWithSAML Detection
    description: Detects the use of AssumeRoleWithSAML, which can indicate potential malicious activity if the source is unexpected.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - lateral-movement
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
      - T1550
      - T1550.001
    data_sources:
      - aws
      - cloudtrail
  - title: AWS UpdateSAMLProvider Detection
    description: Detects updates to the SAML provider, which can indicate an attacker attempting to establish a backdoor.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - persistence
    techniques:
      - T1548
    data_sources:
      - aws
      - cloudtrail
rules_count: 2
---

This detection identifies potentially malicious Security Assertion Markup Language (SAML) activity within Amazon Web Services (AWS). The activity includes monitoring for `AssumeRoleWithSAML` and `UpdateSAMLProvider` events. An adversary might exploit SAML to gain unauthorized access, escalate privileges, move laterally within the AWS environment, or establish persistent backdoor access. The focus is on detecting unusual or unauthorized modifications to SAML configurations and role assumptions, which could indicate a compromised identity provider or malicious actor leveraging SAML for illicit purposes. Defenders should prioritize monitoring SAML-related API calls to identify and mitigate potential threats early in the attack chain.

## Attack Chain

1.  The attacker compromises or creates a malicious SAML identity provider.
2.  The attacker configures the AWS environment to trust the malicious SAML provider using `UpdateSAMLProvider`.
3.  The attacker crafts a SAML assertion to assume a specific role within the AWS environment.
4.  The attacker uses the `AssumeRoleWithSAML` API call to authenticate with AWS using the crafted SAML assertion.
5.  AWS STS validates the SAML assertion and, if valid, provides temporary credentials for the assumed role.
6.  The attacker uses the temporary credentials to perform actions within AWS, potentially escalating privileges.
7.  The attacker moves laterally within the AWS environment, accessing resources and services authorized for the assumed role.
8.  The attacker establishes persistent access by creating backdoors or modifying existing IAM policies, leveraging the initially gained access.

## Impact

Successful exploitation via SAML manipulation can lead to a complete compromise of the AWS environment. Attackers can gain unauthorized access to sensitive data, disrupt critical services, and deploy malicious infrastructure. The impact includes potential data breaches, financial losses, and reputational damage. The number of affected resources depends on the permissions associated with the roles assumed by the attacker.

## Recommendation

*   Deploy the Sigma rule for `AssumeRoleWithSAML` events to detect suspicious role assumptions (see "AssumeRoleWithSAML Detection Rule").
*   Deploy the Sigma rule for `UpdateSAMLProvider` events to detect unauthorized SAML provider modifications (see "UpdateSAMLProvider Detection Rule").
*   Investigate any `AssumeRoleWithSAML` events originating from unfamiliar user agents or IP addresses by reviewing CloudTrail logs.
*   Monitor `UpdateSAMLProvider` events for unexpected changes to SAML provider configurations. Review associated CloudTrail logs for user identity, user agent, and hostname to ensure authorized access.
*   Tune the provided Sigma rules for your environment, addressing false positives by exempting known, legitimate behavior.
