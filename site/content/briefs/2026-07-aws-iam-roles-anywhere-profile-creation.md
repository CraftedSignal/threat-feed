---
title: AWS IAM Roles Anywhere Profile Creation
slug: 2026-07-aws-iam-roles-anywhere-profile-creation
description: Adversaries may create new AWS IAM Roles Anywhere profiles via the 'CreateProfile' API call to establish persistence or escalate privileges within an AWS environment by linking highly privileged roles to a rogue trust anchor, facilitating long-term external access.
date: "2026-07-15T14:18:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - persistence
  - privilege-escalation
vendors:
  - AWS
products:
  - IAM Roles Anywhere
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries who have established persistence through a rogue trust anchor may create or modify profiles to link them with highly privileged roles, enabling long-term external access to the AWS environment.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries who have established persistence through a rogue trust anchor may create or modify profiles to link them with highly privileged roles, enabling long-term external access to the AWS environment.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html
  - https://docs.datadoghq.com/security/default_rules/cloudtrail-aws-iam-roles-anywhere-trust-anchor-created/
  - https://ermetic.com/blog/aws/keep-your-iam-users-close-keep-your-third-parties-even-closer-part-1/
  - https://docs.aws.amazon.com/rolesanywhere/latest/APIReference/API_CreateProfile.html
rules:
  - title: AWS IAM Roles Anywhere Profile Creation
    description: Detects the creation of a new AWS IAM Roles Anywhere profile, which adversaries can use to establish persistence or escalate privileges within an AWS environment.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
      - T1098.003
    data_sources:
      - cloud
      - aws
      - cloudtrail
rules_count: 1
---

This brief details the detection of AWS IAM Roles Anywhere profile creation, a technique adversaries can use to establish persistent access or escalate privileges within an AWS environment. AWS IAM Roles Anywhere enables external workloads and systems to assume IAM roles by authenticating with trusted certificate authorities (CAs), known as trust anchors. Attackers who have compromised or established a rogue trust anchor can leverage the `CreateProfile` API call to define new profiles. These profiles can then be linked to highly privileged IAM roles, granting long-term external access to the AWS infrastructure. Monitoring the creation of such profiles is crucial for identifying unauthorized access configurations and mitigating potential threats to cloud resources. This activity indicates a potential post-compromise action aimed at maintaining control or expanding access.

## Attack Chain

1. An adversary gains initial access to an AWS account, compromising an IAM user or role with permissions to create or modify AWS IAM Roles Anywhere configurations.
2. The adversary establishes or leverages an existing rogue trusted certificate authority (Trust Anchor) within the AWS environment, often through prior compromise or misconfiguration.
3. The adversary invokes the `rolesanywhere:CreateProfile` API call to define a new Roles Anywhere profile, indicating an intent to establish a new external access vector.
4. During profile creation, the adversary configures the new profile to link the rogue `trustAnchorArn` and specifies one or more highly privileged `roleArns` to be assumed.
5. The adversary sets an extended `durationSeconds` for the session, allowing for prolonged external access without repeated authentication.
6. Using a certificate issued by the rogue trust anchor, the adversary calls the `sts:AssumeRoleWithCertificate` API, leveraging the newly created profile.
7. The adversary successfully assumes the highly privileged IAM roles, gaining persistent external access and escalating their privileges within the AWS environment.
8. With elevated access, the adversary can then perform actions such as data exfiltration, resource modification, or further compromise of the AWS infrastructure.

## Impact

Successful exploitation of AWS IAM Roles Anywhere profile creation leads to unauthorized, persistent, and potentially highly privileged external access to an organization's AWS environment. This can result in severe consequences, including data breaches, unauthorized modification or deletion of critical resources, service disruption, and the ability for attackers to further extend their foothold within the cloud infrastructure. The impact is significant as it provides a stealthy and durable mechanism for adversaries to maintain control, bypassing traditional IAM user/role authentication mechanisms and making detection and remediation challenging without specific monitoring.

## Recommendation

* Deploy the Sigma rule `AWS IAM Roles Anywhere Profile Creation` to your SIEM and tune for your environment.
* Enable AWS CloudTrail logging with data events for all services to capture `CreateProfile` API calls.
* Review `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` fields in your CloudTrail logs to identify the actor responsible for profile creation.
* Investigate `aws.cloudtrail.request_parameters` fields, specifically `profileName`, `roleArns`, `trustAnchorArn`, and `durationSeconds`, to ensure profile configurations are legitimate and adhere to the principle of least privilege.
* Correlate `CreateProfile` events with other AWS CloudTrail activities such as `CreateTrustAnchor`, `CreateRole`, `PutRolePolicy`, `AttachRolePolicy`, and `AssumeRoleWithCertificate` to identify a broader attack pattern.
* Restrict `rolesanywhere:CreateProfile` permissions to a minimal set of administrative roles using IAM policies.
* Implement AWS Config or Security Hub controls to continuously monitor for and alert on unauthorized or overly permissive Roles Anywhere profiles.
