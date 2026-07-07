---
title: AWS ECR Repository or Registry Policy Granted Public Access
slug: 2026-07-aws-ecr-public-access
description: A malicious actor or misconfigured legitimate user can modify an Amazon ECR repository or registry policy to grant public access using a wildcard principal (`Principal:"*"`), which can lead to the exfiltration of proprietary container images and embedded secrets, or facilitate supply-chain implantation if push permissions are also granted.
date: "2026-07-03T15:39:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - ecr
  - exfiltration
  - supply-chain
vendors:
  - Amazon
products:
  - Amazon ECR
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: A public container registry can expose proprietary images and any secrets baked into their layers, and, if push is allowed, enables supply-chain implantation.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_SetRepositoryPolicy.html
  - https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/exfiltration_ecr_repository_policy_granted_public_access.toml
rules:
  - title: AWS ECR Repository or Registry Policy Granted Public Access
    description: Detects when an Amazon ECR repository or registry policy is modified to grant public access using a wildcard principal (Principal:"*") statement, indicating potential exfiltration or supply chain compromise risk.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - cloud
      - cloudtrail
rules_count: 1
---

This threat involves the modification of an Amazon Elastic Container Registry (ECR) policy to grant public access, which can be performed by an attacker who has gained initial access to an AWS account or by an insider with appropriate permissions, or inadvertently by a legitimate user. The malicious activity specifically targets the `SetRepositoryPolicy` or `PutRegistryPolicy` API calls to include a policy document with an `Allow` effect for a wildcard principal (`"*"`), effectively opening the container registry to all identities, including unauthenticated users. This misconfiguration, once established, can lead to the exfiltration of sensitive, proprietary container images, including any embedded secrets, posing a significant data breach risk. Furthermore, if the public policy also permits `push` actions, an adversary can implant malicious container images into the registry, leading to a severe supply chain compromise when these backdoored images are subsequently deployed by downstream services such as AWS ECS, EKS, or Lambda workloads.

## Attack Chain

1.  An attacker gains initial access to an AWS account through compromised credentials, insecure access keys, or by exploiting vulnerabilities in connected services.
2.  The attacker, leveraging the compromised credentials, executes an `ecr:SetRepositoryPolicy` or `ecr:PutRegistryPolicy` API call to modify an existing ECR repository or registry policy.
3.  The API request includes a crafted policy document that sets an `Allow` effect for a `Principal` field containing `"*"`, thereby granting public access.
4.  The ECR service successfully processes the policy update, making the specified repository or registry publicly accessible for `pull` actions (e.g., `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`).
5.  The attacker, or any other unauthorized entity, can now pull proprietary container images from the ECR repository, leading to the exfiltration of intellectual property, sensitive configurations, and hardcoded secrets.
6.  (Optional) If the publicly exposed policy also grants `push` permissions (e.g., `ecr:PutImage`, `ecr:UploadLayerPart`), the attacker can push malicious or backdoored container images to the repository.
7.  Downstream services and applications (e.g., AWS ECS tasks, EKS pods, Lambda functions) configured to pull images from this repository will then fetch and deploy the compromised images.
8.  This deployment leads to a supply chain compromise, allowing the attacker to execute arbitrary code, establish persistence, or further expand their presence within the victim's cloud environment.

## Impact

The primary impact of public ECR access is the exfiltration of sensitive data, including proprietary source code, application configurations, and hardcoded secrets (such as API keys, database credentials) that are baked into container images. Organizations across all sectors utilizing AWS ECR are susceptible. If the policy permits push access, the impact escalates to a supply chain attack, where adversaries can inject malicious code into deployed applications, leading to widespread system compromise, data breaches, and potential operational disruption. This could affect numerous downstream services within an organization's cloud infrastructure, potentially compromising customer data or critical business processes.

## Recommendation

*   Deploy the Sigma rule "AWS ECR Repository or Registry Policy Granted Public Access" in this brief to your SIEM and tune for your environment, paying close attention to `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.type`.
*   Review AWS CloudTrail logs for `SetRepositoryPolicy` or `PutRegistryPolicy` events to identify any unauthorized or unintended policy changes.
*   Restrict `ecr:SetRepositoryPolicy` and `ecr:PutRegistryPolicy` permissions within your AWS accounts to only trusted administrators using AWS IAM policies.
*   Ensure that any publicly exposed ECR repositories identified by the Sigma rule are intentionally public, that the access is strictly pull-only, and that their contents do not contain any sensitive data.
*   Regularly audit ECR repository policies for adherence to the principle of least privilege, specifically checking for `Principal:"*"` statements.
