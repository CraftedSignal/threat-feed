---
title: AWS IAM MFA Device Deactivation
slug: 2024-01-aws-iam-mfa-deactivation
description: Detection of AWS IAM MFA device deactivation via the `DeactivateMFADevice` API call, which could indicate an attempt to weaken account protections for privilege escalation or persistence.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - iam
  - mfa
  - deactivation
  - cloudtrail
vendors:
  - AWS
products:
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/deactivate-mfa-device.html
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeactivateMFADevice.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html
  - https://attack.mitre.org/techniques/T1531/
  - https://attack.mitre.org/techniques/T1556/
  - https://attack.mitre.org/techniques/T1556/006/
rules:
  - title: AWS IAM MFA Deactivation
    description: Detects the deactivation of an MFA device in AWS IAM via the DeactivateMFADevice API call.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
      - persistence
    techniques:
      - T1531
      - T1556
      - T1556.006
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
  - title: AWS IAM MFA Deactivation by Unusual Source IP
    description: Detects the deactivation of an MFA device in AWS IAM from a source IP not in a whitelist.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - impact
      - persistence
    techniques:
      - T1531
      - T1556
      - T1556.006
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
rules_count: 2
---

This threat brief focuses on the detection of Multi-Factor Authentication (MFA) device deactivation within AWS Identity and Access Management (IAM). Adversaries, or compromised administrators, may attempt to deactivate MFA devices to weaken account protections, disable strong authentication, and potentially escalate privileges or establish persistence within the AWS environment. The detection strategy hinges on monitoring successful `DeactivateMFADevice` API calls, which represent the event when MFA protection is actively removed from an IAM user. Successful deactivation of MFA makes an AWS account more vulnerable to credential theft and unauthorized access, especially for privileged accounts. Defenders need to be aware of legitimate MFA deactivation events like device rotation or user offboarding, which can cause false positives.

## Attack Chain

1.  Initial compromise of an IAM user's credentials through phishing or credential stuffing.
2.  Attacker logs into the AWS environment using compromised credentials.
3.  Attacker enumerates MFA devices associated with the target IAM user by using API calls like `ListMFADevices`.
4.  Attacker calls `DeactivateMFADevice` to remove the MFA requirement for the targeted user.
5.  The AWS IAM service processes the `DeactivateMFADevice` request and, if authorized based on the attacker's privileges, removes the MFA association.
6.  Attacker may then create new access keys (`CreateAccessKey`) or modify IAM policies (`AttachUserPolicy`) to further their access.
7.  Attacker accesses sensitive AWS resources, such as S3 buckets or EC2 instances, without MFA.
8.  Attacker establishes persistence by creating backdoors or modifying IAM roles to maintain access after the initial compromise is detected.

## Impact

A successful MFA deactivation can lead to unauthorized access to sensitive data, service disruption, or complete account takeover. The impact is magnified when privileged accounts are targeted. The lack of MFA significantly reduces the security posture of the affected AWS account, making it easier for attackers to move laterally within the AWS environment and exfiltrate data. Organizations relying heavily on AWS services could face significant financial losses and reputational damage.

## Recommendation

*   Deploy the Sigma rule `AWS IAM MFA Deactivation` to detect successful `DeactivateMFADevice` API calls (see rule below).
*   Investigate any detected `DeactivateMFADevice` events by reviewing `aws.cloudtrail.user_identity.arn` and `source.ip` to determine the initiator and origin.
*   Enable AWS CloudTrail logging and monitor for IAM configuration changes, focusing on events related to MFA device management.
*   Enforce MFA for all IAM users, particularly those with elevated privileges, using service control policies (SCPs).
*   Implement automated alerts for unusual IAM activity, such as MFA deactivation outside of business hours or from unfamiliar IP addresses.
*   Review CloudTrail logs for related API calls like `ListMFADevices`, `CreateAccessKey`, or `AttachUserPolicy` following the `DeactivateMFADevice` event.
