---
title: AWS STS AssumeRole with New MFA Device
slug: 2026-09-aws-sts-mfa-persistence
description: Adversaries may register new MFA devices for compromised AWS IAM roles to maintain persistence, escalate privileges, or facilitate lateral movement by assuming roles via the AWS Security Token Service (STS).
date: "2026-09-18T19:41:30Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - persistence
  - identity-audit
vendors:
  - Amazon
products:
  - AWS Security Token Service (STS)
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Adversaries may register new MFA devices for compromised AWS IAM roles to maintain persistence.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: Adversaries may exploit new MFA devices to maintain persistence or escalate privileges.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: The detection rule identifies successful role assumptions with new MFA devices, flagging potential misuse for lateral movement.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
  - https://github.com/RhinoSecurityLabs/cloudgoat/blob/d5863b80afd082d853f2e8df1955c6393695a4da/scenarios/iam_privesc_by_key_rotation/README.md
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review CloudTrail logs for AssumeRole events referencing new MFA serial numbers.
      owner: SOC
      due: 24h
      evidence: Detection rule logic requires verification of request_parameters.serialNumber
  hunt_leads:
    - lead: Identify IAM users who have registered new MFA devices in the last 30 days.
      technique_id: T1556.006
      data_needed:
        - 'CloudTrail Event: CreateVirtualMFADevice'
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Registration of new MFA devices is a precursor to the observed AssumeRole behavior.
  mitigation_plan:
    - priority: medium
      action: Implement IAM policies restricting MFA device management to authorized administrative roles.
      owner: IT Operations
      addresses: T1556.006
      evidence: IAM best practices for security and access control.
---

Adversaries targeting AWS environments may attempt to register new Multi-Factor Authentication (MFA) devices against compromised IAM identities to secure long-term access. By leveraging the AWS Security Token Service (STS) `AssumeRole`, `AssumeRoleWithSAML`, or `AssumeRoleWithWebIdentity` APIs, an attacker with valid but potentially limited credentials can perform privilege escalation or lateral movement. The registration of a new MFA device serves as a mechanism to bypass or supersede existing authentication requirements, granting the adversary persistent access to the assumed role's permissions. Defenders should monitor CloudTrail for successful role assumptions that reference previously unseen MFA serial numbers, as this pattern often deviates from standard administrative workflows or automated service account behavior.

## Attack Chain

1. An attacker gains initial access to a set of AWS IAM credentials (e.g., via hardcoded keys, leaked environment variables, or SSRF).
2. The attacker uses the compromised credentials to query current IAM user permissions and MFA device configurations.
3. The attacker registers a new, attacker-controlled MFA device (e.g., virtual MFA) to the compromised IAM user account via `CreateVirtualMFADevice`.
4. The attacker associates the new MFA device with the target IAM role or user using `EnableMFADevice`.
5. The attacker executes `AssumeRole` or a related STS action, providing the new MFA serial number in the request parameters.
6. AWS validates the new MFA token, and the attacker receives temporary security credentials.
7. The attacker leverages the elevated temporary session credentials to access, exfiltrate, or manipulate AWS resources.

## Impact

Successful exploitation allows an adversary to maintain persistent access to an AWS account, escalate privileges beyond the initial scope, and move laterally across different accounts or services. This activity can lead to unauthorized data exfiltration, service disruption, or total account takeover depending on the IAM policies attached to the assumed role.

## Recommendation

Prioritize monitoring of AWS CloudTrail logs for unusual `AssumeRole` events. Establish a baseline for normal MFA registrations and role assumptions to reduce false positives from legitimate administrative tasks. 

- Implement alerts for successful `AssumeRole` events where the `request_parameters.serialNumber` field is present and indicates a newly registered device.
- Review all MFA device registration events (e.g., `CreateVirtualMFADevice`) alongside `AssumeRole` activity to identify unauthorized additions.
- Revoke temporary credentials immediately if a role assumption is linked to an unauthorized MFA device registration.
- Audit IAM policies to ensure that only authorized users have the permission to manage their own MFA devices.
