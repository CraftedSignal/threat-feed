---
title: AWS IAM Key Creation with Encryption Policy but Without MFA
slug: 2024-01-aws-key-creation-no-mfa
description: Detection of AWS IAM users creating access keys with encryption policies applied while failing to use multi-factor authentication, potentially indicating compromised accounts or malicious privilege escalation.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - iam
  - access_key
  - encryption
  - mfa
vendors:
  - AWS
products:
  - Identity and Access Management
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_detect_users_creating_keys_with_encrypt_policy_without_mfa.yml
rules:
  - title: AWS IAM Key Creation with Encryption Policy but Without MFA
    description: Detects AWS IAM user creating access key with encryption policy without MFA.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM Policy Modification Without MFA
    description: Detects modification of AWS IAM policies without multi-factor authentication.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief focuses on identifying potentially malicious activity within Amazon Web Services (AWS) environments related to Identity and Access Management (IAM). Specifically, it addresses the scenario where an IAM user creates a new access key and associates an encryption policy with it, but does not authenticate using multi-factor authentication (MFA). Such behavior can indicate a compromised user account being used to escalate privileges or establish persistent access, or an insider threat attempting to bypass security controls. This activity is important to detect as it allows attackers to encrypt data and make it inaccessible without proper authorization.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account, potentially through credential theft or other means.
2. The attacker attempts to create a new IAM user or assume an existing IAM role to gain greater control over AWS resources.
3. The attacker creates a new access key associated with either the compromised user or newly created/assumed role.
4. The attacker attaches an encryption policy to the created access key, granting it the ability to encrypt data at rest or in transit.
5. The creation of the access key and attachment of the encryption policy occurs without requiring MFA, indicating a bypass of security best practices.
6. The attacker uses the newly created access key to encrypt sensitive data stored in services like S3, EBS, or RDS.
7. The attacker might then attempt to exfiltrate the encrypted data or hold it for ransom, impacting confidentiality and availability.

## Impact

Successful exploitation could lead to unauthorized encryption of sensitive data within AWS, rendering it inaccessible to legitimate users without the attacker's keys. This could result in significant business disruption, data loss, and compliance violations. The number of affected resources would depend on the scope of the compromised access key's permissions and the attacker's objectives. The impact could range from encrypting a single critical database to locking down an entire AWS environment.

## Recommendation

*   Deploy the Sigma rule `AWS IAM Key Creation with Encryption Policy but Without MFA` to your SIEM to detect this specific activity.
*   Enable and enforce MFA for all IAM users, especially those with administrative privileges or access to sensitive resources, to prevent unauthorized access key creation.
*   Review IAM policies to ensure least privilege and limit the scope of access keys.
*   Monitor AWS CloudTrail logs for suspicious IAM activity, including access key creation and policy attachments, as indicated by the logsource in the Sigma rules.
