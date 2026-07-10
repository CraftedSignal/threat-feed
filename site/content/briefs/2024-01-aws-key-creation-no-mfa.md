---
title: AWS IAM Key Creation with Encryption Policy but without MFA
slug: 2024-01-aws-key-creation-no-mfa
description: An AWS IAM user is creating keys and applying encryption policies without multi-factor authentication (MFA), potentially indicating an attempt to establish persistent access and bypass security controls.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - iam
  - key-creation
  - mfa-bypass
  - persistence
vendors:
  - Amazon
products:
  - AWS
  - IAM
  - KMS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_detect_users_creating_keys_with_encrypt_policy_without_mfa.yml
rules:
  - title: AWS IAM Key Creation with Encryption Policy but without MFA
    description: Detects AWS IAM user creating a new access key and assigning encryption-related policies without MFA.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM Policy Modification without MFA
    description: Detects AWS IAM Policy modifications without MFA which may lead to privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This alert focuses on identifying potentially malicious activity within Amazon Web Services (AWS) environments where Identity and Access Management (IAM) users are creating new access keys and associating them with encryption-related policies without proper multi-factor authentication (MFA). This behavior could indicate an attacker attempting to establish persistent access to the AWS environment, bypass security controls, and potentially exfiltrate or encrypt data. Although the source does not specify the exact scope or targeting, this detection aims to identify a common tactic used in cloud-based attacks to escalate privileges and maintain unauthorized access. Identifying and investigating these events promptly is crucial for maintaining the security posture of AWS environments.

## Attack Chain

1.  An attacker gains initial access to an AWS account, possibly through compromised credentials or other means.
2.  The attacker attempts to create a new IAM user or utilizes an existing IAM user account.
3.  The attacker attempts to create a new IAM access key.
4.  The attacker attempts to assign an IAM policy to the user or key that grants permissions related to encryption services, such as KMS (Key Management Service).
5.  The attacker performs these actions without triggering MFA.
6.  The newly created key, if successful, is used to access AWS resources and services.
7.  The attacker leverages the encryption permissions to encrypt data, potentially for ransomware purposes, or to gain unauthorized access to encrypted resources.
8.  The attacker establishes persistence within the AWS environment, enabling long-term unauthorized access and control.

## Impact

Successful exploitation could allow an attacker to gain persistent access to an AWS environment, bypass MFA controls, and escalate privileges. This can lead to unauthorized data access, exfiltration of sensitive information, or encryption of critical data for ransom. The impact ranges from data breaches and service disruption to significant financial losses. Identifying and mitigating such activities is critical for organizations relying on AWS infrastructure.
