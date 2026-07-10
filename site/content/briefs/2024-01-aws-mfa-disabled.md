---
title: AWS Multi-Factor Authentication Disabled
slug: 2024-01-aws-mfa-disabled
description: Detection of AWS Multi-Factor Authentication (MFA) being disabled for an IAM user, indicating potential weakening of account security and persistence attempts.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloudtrail
  - mfa
  - iam
  - persistence
vendors:
  - AWS
products:
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1621
    technique_name: Compromise Security Software
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1586
    technique_name: Compromise Account
references:
  - https://attack.mitre.org/techniques/T1621/
  - https://aws.amazon.com/what-is/mfa/
rules:
  - title: Detect AWS MFA Deactivation
    description: Detects attempts to deactivate MFA for an AWS IAM user.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1621
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS Virtual MFA Device Deletion
    description: Detects attempts to delete virtual MFA device for an AWS IAM user.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1621
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief addresses the potential for attackers to disable Multi-Factor Authentication (MFA) on AWS IAM accounts. The activity is detected through AWS CloudTrail logs by monitoring for `DeleteVirtualMFADevice` or `DeactivateMFADevice` events. This activity, while potentially legitimate, is a critical indicator of compromise because disabling MFA significantly reduces the security posture of an AWS account. An attacker with compromised credentials might disable MFA to establish persistence and retain unauthorized access to AWS resources. Successfully disabling MFA allows attackers to move laterally within the AWS environment and conduct malicious activities without triggering MFA-based security controls. This is particularly concerning if the affected account has privileged access.

## Attack Chain

1. An attacker gains initial access to an AWS IAM user's credentials, potentially through credential stuffing or phishing.
2. The attacker authenticates to the AWS Management Console or via the AWS CLI using the compromised credentials.
3. The attacker identifies that MFA is enabled on the compromised account.
4. The attacker initiates the `DeactivateMFADevice` API call to remove the MFA association from the user account.
5. Alternatively, the attacker initiates the `DeleteVirtualMFADevice` API call to delete the virtual MFA device.
6. AWS CloudTrail logs the `DeactivateMFADevice` or `DeleteVirtualMFADevice` event.
7. With MFA disabled, the attacker maintains persistent access to the AWS environment.
8. The attacker performs unauthorized actions, such as data exfiltration, resource modification, or lateral movement, without MFA protection.

## Impact

Successful disabling of MFA on an AWS IAM account can lead to significant security breaches. The attacker gains persistent access to the AWS environment, enabling data exfiltration, unauthorized resource modification, and lateral movement. This can result in data loss, service disruption, and financial damages. The impact is amplified if the compromised account has administrative privileges, potentially affecting critical AWS services and resources.

## Recommendation

*   Deploy the Sigma rule `Detect AWS MFA Deactivation` to your SIEM and tune for your environment.
*   Enable AWS CloudTrail logging and ensure logs are being ingested into your SIEM to detect the events described in this brief.
*   Investigate any instances of `DeleteVirtualMFADevice` or `DeactivateMFADevice` events in AWS CloudTrail to determine if they are legitimate administrative actions.
*   Implement strict MFA enforcement policies and regularly audit MFA status across all IAM users to prevent unauthorized disabling of MFA.
