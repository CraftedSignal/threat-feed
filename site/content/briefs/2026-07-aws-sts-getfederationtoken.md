---
title: AWS STS GetFederationToken Abuse for Persistence and Defense Evasion
slug: 2026-07-aws-sts-getfederationtoken
description: Adversaries may exploit the AWS Security Token Service (STS) GetFederationToken API call to obtain temporary security credentials, enabling persistence and bypassing IAM API call limitations by gaining console access, with these temporary tokens remaining active for up to 36 hours, even if the initial compromised identity is deleted, and used to create console sign-in tokens.
date: "2026-07-15T14:01:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - defense-evasion
  - persistence
  - threat-detection
vendors:
  - AWS
products:
  - AWS Security Token Service
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Adversaries may use this API to obtain temporary credentials for persistence and to bypass IAM API call limitations by gaining console access.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: These credentials will remain active for the duration specified (maximum 36 hours), even if the initial compromised identity is deleted.
    confidence_band: high
references:
  - https://hackingthe.cloud/aws/post_exploitation/survive_access_key_deletion_with_sts_getfederationtoken/
  - https://www.crowdstrike.com/en-us/blog/how-adversaries-persist-with-aws-user-federation/
  - https://medium.com/@adan.alvarez/how-attackers-persist-in-aws-using-getfederationtoken-a-simple-and-effective-technique-used-in-the-987ec1f0bdfe/
rules:
  - title: AWS First Occurrence of STS GetFederationToken Request by User
    description: Detects the first occurrence of an AWS Security Token Service (STS) GetFederationToken request made by a user. Adversaries may use this API to obtain temporary credentials for persistence and to bypass IAM API call limitations by gaining console access.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1098
      - T1098.001
      - T1550
      - T1550.001
    data_sources:
      - cloud
      - aws
      - cloudtrail
rules_count: 1
---

Adversaries are known to abuse the AWS Security Token Service (STS) `GetFederationToken` API call as a method for defense evasion and persistence in compromised AWS environments. This technique allows an attacker, typically after compromising an IAM user or role, to request temporary security credentials. These temporary tokens can grant access to AWS resources and remain valid for up to 36 hours, critically maintaining access even if the original compromised identity's credentials are revoked or deleted. Furthermore, these federated tokens can be used to generate console sign-in tokens, providing attackers with interactive console access and potentially bypassing IAM API call limitations. The detection focuses on the first occurrence of such a request by a user, indicating unusual activity that could signify an attacker establishing a persistent foothold or evading existing security controls.

## Attack Chain

1. **Initial Access**: Adversary compromises an AWS account, typically by obtaining legitimate IAM user credentials (e.g., access key and secret key) through phishing, exposed credentials, or other means.
2. **Discovery/Credential Access**: Using the compromised credentials, the attacker enumerates IAM permissions and identifies the ability to call `sts:GetFederationToken`.
3. **Defense Evasion & Persistence**: The attacker calls the `GetFederationToken` API with the compromised credentials to obtain temporary security credentials (access key, secret key, session token) for a federated user. This action establishes a new, temporary identity.
4. **Credential Manipulation**: The attacker stores these temporary credentials, which provide a valid session to AWS, independent of the original compromised credentials.
5. **Persistence**: Even if the original compromised IAM user's credentials are deleted or revoked, the temporary federated tokens remain active for their specified duration (up to 36 hours), granting the attacker continued access.
6. **Privilege Escalation/Execution**: The attacker uses the temporary federated credentials to access AWS resources, perform actions, or generate a console sign-in URL to gain interactive console access, potentially bypassing API limitations and performing sensitive IAM operations.
7. **Impact**: Continued unauthorized access, data exfiltration, resource modification, or deployment of additional malicious infrastructure.

## Impact

A successful `GetFederationToken` abuse leads to sustained unauthorized access within the AWS environment. This persistence mechanism allows attackers to maintain control over an AWS account even after initial compromise vectors are remediated, significantly prolonging incident response efforts. Attackers can exfiltrate sensitive data, disrupt critical services, or deploy additional infrastructure using the federated credentials. The ability to generate console sign-in tokens further expands the attacker's operational capabilities, allowing them to interact with services through the AWS Management Console as a legitimate user, making detection and containment more challenging.

## Recommendation

* Deploy the Sigma rule `AWS First Occurrence of STS GetFederationToken Request by User` in this brief to your SIEM and tune for your environment, paying close attention to `data_stream.dataset: "aws.cloudtrail"` logs.
* Review the `user.name`, `aws.cloudtrail.user_identity.arn`, and `source.ip` fields in CloudTrail logs for any `GetFederationToken` requests to identify unexpected user accounts or geographical locations.
* Investigate the `aws.cloudtrail.response_elements` field in logs for newly created `federatedUser.arn` values and monitor their subsequent activities.
* Implement strong IAM policies that restrict the ability to call `sts:GetFederationToken` to only necessary roles or users to minimize the attack surface.
* If compromise is verified, attach the AWS-managed policy `AWSDenyAll` to the compromised IAM principal to immediately revoke all associated temporary credentials.
