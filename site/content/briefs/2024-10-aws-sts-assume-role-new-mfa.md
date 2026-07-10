---
title: AWS STS AssumeRole with New MFA Device
slug: 2024-10-aws-sts-assume-role-new-mfa
description: This rule identifies when a user has assumed a role using a new MFA device in AWS, which can be indicative of persistence and privilege escalation attempts by threat actors.
date: "2024-10-26T12:00:00Z"
type: threat
types:
  - threat
severities:
  - low
exploited: true
tags:
  - aws
  - cloudtrail
  - sts
  - assume_role
  - mfa
  - persistence
  - privilege_escalation
  - lateral_movement
vendors:
  - AWS
products:
  - AWS Security Token Service
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
  - https://github.com/RhinoSecurityLabs/cloudgoat/blob/d5863b80afd082d853f2e8df1955c6393695a4da/scenarios/iam_privesc_by_key_rotation/README.md
rules:
  - title: AWS STS AssumeRole with New MFA Device - Serial Number Present
    description: Detects AWS STS AssumeRole events with a serial number in the request parameters, indicating the use of an MFA device.
    platform: sigma
    severity: low
    tactics:
      - lateral_movement
      - persistence
      - privilege_escalation
    techniques:
      - T1078.004
      - T1550
      - T1556.006
    data_sources:
      - cloudtrail
      - aws
  - title: AWS STS AssumeRole - No Source Identity
    description: Detects AWS STS AssumeRole events without a source identity, which could indicate potential credential abuse.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1550
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection rule identifies instances of AWS Security Token Service (STS) `AssumeRole` calls where a new Multi-Factor Authentication (MFA) device is used. While legitimate administrative tasks may involve assuming roles with new MFA devices, adversaries can leverage this technique to establish persistence, escalate privileges, or move laterally within an AWS environment. The rule focuses on successful `AssumeRole`, `AssumeRoleWithSAML`, and `AssumeRoleWithWebIdentity` events, specifically looking for the presence of a serial number associated with the MFA device in the request parameters, indicating a new MFA device was used. This activity warrants investigation to determine if it is authorized or indicative of malicious behavior. The rule uses a 10-day history window to define "new" MFA devices.

## Attack Chain

1. An attacker gains initial access to an AWS account, potentially through compromised credentials (T1078.004).
2. The attacker registers a new MFA device within the compromised AWS account (T1556.006).
3. The attacker uses the AWS STS `AssumeRole` API to request temporary credentials for a different IAM role (T1550).
4. The request includes the serial number of the newly registered MFA device in the `request_parameters` (part of the AssumeRole call).
5. AWS STS validates the MFA and, if successful, issues temporary credentials associated with the assumed role (T1550.001).
6. The attacker uses these temporary credentials to access resources and perform actions authorized by the assumed role (T1078).
7. This may involve escalating privileges, accessing sensitive data, or moving laterally to other AWS resources (TA0004, TA0008).

## Impact

A successful attack using a new MFA device to assume a role can lead to unauthorized access to sensitive AWS resources. The attacker can escalate privileges, move laterally to other resources, or establish persistent access within the environment. This can result in data breaches, service disruption, or other malicious activities, impacting the confidentiality, integrity, and availability of the organization's cloud infrastructure. The risk score is 21, indicating a potential but not immediately critical threat.

## Recommendation

*   Deploy the following Sigma rules to your SIEM to detect the use of new MFA devices in `AssumeRole` calls and tune for your environment.
*   Enable AWS CloudTrail logging and ensure proper configuration of the AWS Fleet integration or Filebeat module to capture relevant STS events.
*   Review AWS CloudTrail logs for unusual patterns of MFA device registrations and role assumptions, focusing on privilege escalation or lateral movement attempts.
*   Implement additional monitoring and alerting for unusual MFA device registrations and role assumptions to enhance detection of similar threats in the future.
*   Create exceptions for known onboarding activities or routine device replacements by correlating with HR records or IT support tickets as described in the rule's false positives section.
