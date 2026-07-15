---
title: AWS IAM Multi-Factor Authentication Device Deactivation
slug: 2026-07-aws-iam-mfa-deactivation
description: Adversaries or compromised administrators may deactivate Multi-Factor Authentication (MFA) devices in AWS Identity and Access Management (IAM) by executing a successful `DeactivateMFADevice` API call, significantly weakening account security, disabling strong authentication, and paving the way for unauthorized access, privilege escalation, or persistence.
date: "2026-07-15T14:11:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - iam
  - impact
  - persistence
  - defense-evasion
vendors:
  - Amazon
products:
  - AWS Identity and Access Management (IAM)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
    evidence: MFA provides critical protection against unauthorized access by requiring a second factor for authentication. Adversaries or compromised administrators may deactivate MFA devices to weaken account protections, disable strong authentication, or prepare for privilege escalation or persistence.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: Adversaries or compromised administrators may deactivate MFA devices to weaken account protections, disable strong authentication, or prepare for privilege escalation or persistence.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: Adversaries or compromised administrators may deactivate MFA devices to weaken account protections, disable strong authentication, or prepare for privilege escalation or persistence.
    confidence_band: high
references:
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/deactivate-mfa-device.html
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeactivateMFADevice.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html
rules:
  - title: AWS IAM Deactivation of MFA Device
    description: Detects the deactivation of a Multi-Factor Authentication (MFA) device in AWS Identity and Access Management (IAM). MFA provides critical protection against unauthorized access by requiring a second factor for authentication. Adversaries or compromised administrators may deactivate MFA devices to weaken account protections, disable strong authentication, or prepare for privilege escalation or persistence. This rule monitors successful DeactivateMFADevice API calls, which represent the point at which MFA protection is actually removed.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - impact
      - persistence
    techniques:
      - T1531
      - T1556.006
    data_sources:
      - aws.cloudtrail
rules_count: 1
---

Adversaries or compromised administrators are deactivating Multi-Factor Authentication (MFA) devices in AWS Identity and Access Management (IAM) through successful `DeactivateMFADevice` API calls. This action, often observed post-initial access, represents a critical step for attackers to weaken account security and establish persistence. By removing MFA, threat actors can bypass a crucial authentication layer, making accounts vulnerable to unauthorized access, credential stuffing, or further privilege escalation without the need for a second factor. This activity is typically detected via AWS CloudTrail logs, which record API operations. The primary objective is to facilitate easier, persistent access to compromised AWS environments, ensuring continued control over an account and its associated resources, thus reducing the resilience of the target AWS account against credential theft.

## Attack Chain

1. **Initial Access**: An attacker gains initial access to an AWS environment, typically through compromised IAM user credentials, API keys, or an exploited vulnerable service.
2. **Reconnaissance**: The attacker enumerates IAM users and their associated MFA devices to identify targets with MFA enabled, potentially using API calls like `ListMFADevices` or `ListUsers`.
3. **Privilege Escalation / Defense Evasion Planning**: The attacker identifies an IAM user with sufficient permissions to manage MFA devices, targeting them to remove a critical security control.
4. **MFA Device Deactivation**: The attacker executes a successful `DeactivateMFADevice` API call, removing the multi-factor authentication requirement for the targeted IAM user.
5. **Persistence Establishment**: With MFA disabled, the attacker establishes persistence by ensuring future logins do not require a second factor, thus maintaining easier access to the compromised account.
6. **Credential Modification / Lateral Movement**: Following MFA deactivation, the attacker may create new access keys (`CreateAccessKey`), modify user policies (`AttachUserPolicy`), or delete the virtual MFA device (`DeleteVirtualMFADevice`) to solidify their control and move laterally within the AWS environment.
7. **Impact Fulfillment**: The attacker leverages the weakened account security to achieve their final objective, such as accessing sensitive data, deploying malicious infrastructure, or exfiltrating information.

## Impact

The deactivation of an MFA device in AWS IAM significantly reduces the security posture of an affected account by removing a critical layer of authentication. If successful, this enables unauthorized actors to gain unhindered access to the AWS environment using only a stolen username and password. This can lead to broader account compromise, unauthorized resource deployment, data exfiltration from S3 buckets or databases, and service disruption. The impact includes potential financial loss due to unauthorized resource usage, reputational damage, and severe compliance violations, especially in regulated industries. While specific victim counts are not provided, any organization utilizing AWS IAM is a potential target.

## Recommendation

* Deploy the Sigma rule "AWS IAM Deactivation of MFA Device" to your SIEM to detect successful `DeactivateMFADevice` API calls.
* Configure AWS CloudTrail logging to capture `event.provider: iam.amazonaws.com` events, specifically focusing on `event.action: DeactivateMFADevice` and `event.outcome: success`.
* Investigate all instances of `DeactivateMFADevice` activity by reviewing `aws.cloudtrail.user_identity.arn`, `aws.cloudtrail.user_identity.access_key_id`, `user_agent.original`, `source.ip`, and `source.geo` fields for unusual origins or unrecognized locations.
* Correlate `DeactivateMFADevice` events with preceding API calls such as `ListMFADevices`, `GetSessionToken`, or `ListUsers`, and subsequent calls like `DeleteVirtualMFADevice`, `CreateAccessKey`, or `AttachUserPolicy`.
* Implement AWS GuardDuty or Security Hub findings for IAM anomaly detection related to account takeover or configuration changes.
* Require MFA for all privileged IAM users and enforce it using Service Control Policies (SCPs) where applicable.
