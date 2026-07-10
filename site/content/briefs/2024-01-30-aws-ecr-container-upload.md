---
title: Suspicious AWS ECR Container Upload by Unknown User
slug: 2024-01-30-aws-ecr-container-upload
description: This alert detects a container image upload to an AWS Elastic Container Registry (ECR) repository by a user that is not typically associated with such actions, potentially indicating account compromise or insider threat activity.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - ecr
  - cloud
  - container
vendors:
  - AWS
products:
  - Elastic Container Registry
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_ecr_container_upload_unknown_user.yml
rules:
  - title: AWS ECR Image Upload by Uncommon User
    description: Detects an AWS ECR image upload event performed by a user not typically associated with this action.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - aws
  - title: AWS ECR Image Upload to Uncommon Repository
    description: Detects an AWS ECR image upload event to a repository not typically used.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies unusual activity related to AWS Elastic Container Registry (ECR). Specifically, it focuses on container image uploads performed by users or roles that do not typically execute such actions. This activity might indicate a compromised AWS account, a malicious insider, or the use of stolen credentials. While the provided source material lacks specific details on observed campaigns or threat actors, detecting anomalous ECR upload behavior is crucial for maintaining the integrity of containerized applications and preventing the deployment of malicious images. The alert helps defenders identify deviations from the established baseline of ECR usage within their AWS environment.

## Attack Chain

Given the limited information, a generic attack chain is constructed based on the *potential* exploitation of this type of event:

1.  **Initial Access:** An attacker gains unauthorized access to an AWS account, potentially through compromised credentials or exploiting a misconfigured IAM role.
2.  **Privilege Escalation (Optional):** The attacker may attempt to elevate privileges within the AWS environment to gain broader control over resources.
3.  **ECR Access:** The attacker gains access to the AWS ECR service, potentially using the compromised credentials or a role with sufficient permissions.
4.  **Image Modification/Upload:** The attacker uploads a malicious container image to an existing ECR repository, replacing or adding to the available images.
5.  **Deployment Manipulation:** The attacker modifies deployment configurations (e.g., Kubernetes manifests, ECS task definitions) to utilize the newly uploaded malicious image.
6.  **Execution:** The malicious container image is deployed and executed within the environment, leading to further compromise or data exfiltration.
7.  **Persistence:** The attacker may establish persistence within the compromised environment by maintaining access to the AWS account or through other means.

## Impact

Successful exploitation could lead to the deployment of compromised applications within the AWS environment. This could result in data breaches, system compromise, or disruption of services. The number of potential victims depends on the scope of the compromised AWS account and the applications deployed using the affected container images. The targeted sectors are highly variable but could include any organization utilizing AWS ECR for containerized application deployment. The financial and reputational damage could be significant, especially if sensitive data is exposed or services are disrupted.
