---
title: AWS SAML Identity Provider Modification
slug: 2024-01-aws-saml-update-identity-provider
description: An adversary may attempt to modify the AWS SAML Identity Provider configuration to potentially escalate privileges or disrupt federated access.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - saml
  - identity-provider
  - privilege-escalation
vendors:
  - AWS
products:
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1556
    technique_name: Impair Accounts
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_saml_update_identity_provider.yml
rules:
  - title: Detect AWS SAML Identity Provider Update via CloudTrail
    description: Detects modification of an AWS SAML Identity Provider configuration by monitoring CloudTrail logs for the `UpdateSAMLIdentityProvider` API call.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1556.006
    data_sources:
      - cloudtrail
      - aws
  - title: Detect IAM Role Assume with Unusual SAML Provider ARN
    description: Detects an IAM role being assumed using a SAML provider ARN that deviates from expected norms, suggesting a potential misconfiguration or malicious update of the SAML provider.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1552.005
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This brief focuses on the potential modification of AWS SAML Identity Provider (IdP) configurations. While specific threat actors and campaigns are not detailed in the provided source, the action itself is a security concern. An attacker who gains sufficient privileges within an AWS environment might attempt to alter the SAML IdP settings to manipulate user access, potentially granting themselves elevated permissions or disrupting legitimate user authentication. This type of attack impacts cloud security by subverting federated identity management. Defenders should monitor for unexpected changes to SAML configurations.

## Attack Chain

1.  Initial compromise of an AWS account with sufficient permissions to modify IAM resources (e.g., via compromised credentials or an EC2 instance with an overly permissive role).
2.  The attacker uses the AWS CLI or the AWS Management Console to list existing SAML Identity Providers.
3.  The attacker identifies the target SAML Identity Provider to modify.
4.  The attacker modifies the SAML metadata document associated with the Identity Provider, potentially injecting malicious claims or altering role mappings.
5.  The attacker updates the SAML Identity Provider configuration in AWS IAM with the modified metadata document using the `UpdateSAMLIdentityProvider` API call.
6.  The attacker tests the modified configuration to ensure it achieves the desired privilege escalation or access disruption.
7.  Legitimate users attempt to authenticate via SAML, potentially receiving incorrect roles/permissions or being denied access.

## Impact

Successful modification of an AWS SAML Identity Provider can have significant consequences. An attacker could escalate their privileges within the AWS environment, gaining access to sensitive data and resources. They may also disrupt legitimate user access, leading to denial-of-service conditions for federated users. While the scale of impact depends on the scope of the compromised AWS account and the criticality of the federated applications, this attack can severely compromise cloud security.
