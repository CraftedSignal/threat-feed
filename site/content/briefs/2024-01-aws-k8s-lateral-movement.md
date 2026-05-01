---
title: AWS Lateral Movement from Kubernetes Service Account via AssumeRoleWithWebIdentity
slug: 2024-01-aws-k8s-lateral-movement
description: This rule detects lateral movement in AWS environments originating from Kubernetes service accounts by identifying instances where credentials obtained for a service account are used for multiple distinct AWS control-plane actions, potentially indicating unauthorized access.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - kubernetes
  - lateral-movement
  - credential-access
  - discovery
vendors:
  - Amazon
products:
  - AWS CloudTrail
  - EKS IAM Roles for Service Accounts
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
  - https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
rules:
  - title: AWS AssumeRoleWithWebIdentity Followed by Multiple Control Plane Actions
    description: Detects when credentials assumed via AssumeRoleWithWebIdentity are used for multiple distinct AWS control plane actions.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
      - lateral_movement
    techniques:
      - T1021.007
      - T1526
      - T1550.001
      - T1555.006
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Lateral Movement via AssumeRoleWithWebIdentity - Multiple Actions
    description: Detects lateral movement in AWS environments originating from Kubernetes service accounts by identifying multiple distinct AWS control-plane actions after AssumeRoleWithWebIdentity.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
      - lateral_movement
    techniques:
      - T1021.007
      - T1526
      - T1550.001
      - T1555.006
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection rule identifies lateral movement in AWS environments stemming from Kubernetes service accounts utilizing `AssumeRoleWithWebIdentity`. It focuses on detecting instances where credentials obtained via this method are subsequently used to perform several distinct AWS control-plane actions within a single session. This behavior deviates from typical pod traffic and could signify unauthorized access or privilege escalation. The rule prioritizes the detection of sensitive API usage, including reconnaissance activities, access to secrets, IAM modifications, and compute creation events, while strategically excluding high-volume S3 data-plane operations to minimize false positives. The targeted environments are those leveraging EKS IAM Roles for Service Accounts.

## Attack Chain

1. A Kubernetes service account projects a token.
2. The service account uses `AssumeRoleWithWebIdentity` to exchange the token for short-lived IAM credentials.
3. The attacker leverages the assumed role to perform reconnaissance activities such as `ListUsers`, `ListRoles`, and `DescribeInstances`.
4. The attacker attempts to access secrets using actions like `GetSecretValue` and `ListSecrets`.
5. The attacker escalates privileges by modifying IAM policies with actions like `AttachRolePolicy` and `PutRolePolicy`.
6. The attacker attempts to create new users or roles within the AWS environment using actions like `CreateUser` and `CreateRole`.
7. The attacker performs lateral movement using actions like `SendCommand` and `StartSession`.
8. The attacker attempts to evade detection by stopping logging with the `StopLogging` action.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, privilege escalation, and the potential compromise of the entire AWS environment. Lateral movement within the AWS infrastructure allows attackers to gain access to critical systems and data, potentially leading to data breaches, service disruptions, or other malicious activities.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect potentially malicious activity related to `AssumeRoleWithWebIdentity` and tune for your environment.
*   Review and harden IAM role trust policies associated with Kubernetes service accounts, specifically focusing on OIDC trust conditions, as referenced in the [IAM OIDC identity provider](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html) documentation.
*   Implement strict least privilege principles for Kubernetes service accounts, limiting their access to only the necessary AWS resources, as covered in [EKS IAM roles for service accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html).
*   Monitor CloudTrail logs for `AssumeRoleWithWebIdentity` events followed by suspicious API calls, focusing on the actions listed in the Sigma rule detection patterns.
