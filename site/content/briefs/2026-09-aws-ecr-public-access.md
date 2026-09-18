---
title: AWS ECR Repository or Registry Policy Granted Public Access
slug: 2026-09-aws-ecr-public-access
description: Detection of unauthorized configuration changes to AWS ECR policies that grant public access via wildcard principals, potentially leading to container image exfiltration or supply chain implantation.
date: "2026-09-18T19:32:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - exfiltration
  - ecr
vendors:
  - Amazon
products:
  - Elastic Container Registry
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: A public ECR repository allows anyone to pull its images, exposing proprietary code and any secrets embedded in image layers.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_SetRepositoryPolicy.html
  - https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html
rules:
  - title: Detect AWS ECR Policy Allowing Public Access
    description: Detects SetRepositoryPolicy or PutRegistryPolicy events where the policy document grants an Allow effect to a wildcard principal, indicating potential public exposure.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for ECR policy modifications involving wildcard principals.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific logic for detection.
  mitigation_plan:
    - priority: immediate
      action: 'Audit all existing ECR repositories to identify and restrict any ''Principal: *'' policies to authorized users only.'
      owner: IT Operations
      addresses: ECR policy misconfigurations
      evidence: Source documentation identifies this as an exfiltration risk.
---

This threat brief focuses on the misconfiguration of AWS Elastic Container Registry (ECR) policies, where repository or registry permissions are set to allow access to any principal. By modifying these policies via 'SetRepositoryPolicy' or 'PutRegistryPolicy' API calls to include an 'Allow' effect for a wildcard principal (Principal: "*"), an attacker or a misinformed administrator can expose private container images to the public internet. This exposure allows unauthorized, unauthenticated users to download proprietary images, potentially revealing sensitive source code, configuration secrets, or credentials baked into image layers. If the policy also grants write access, it facilitates supply-chain attacks, enabling malicious actors to inject compromised images into the environment, which downstream services like Amazon EKS, ECS, or Lambda may then execute. While intentional public image distribution is a valid use case for ECR, unauthorized changes often signal improper security management or malicious activity.

## Impact

Successful exploitation of this misconfiguration results in the loss of intellectual property through unauthorized image pulling and exposes the organization to supply-chain compromise if push access is erroneously granted. Such vulnerabilities have direct consequences for data integrity and confidentiality in cloud-native environments.

## Recommendation

Prioritize the identification of ECR repositories currently configured with wildcard access and evaluate their necessity.
- Implement detection for 'SetRepositoryPolicy' and 'PutRegistryPolicy' events within AWS CloudTrail to monitor for changes granting 'Allow' permissions to 'Principal: "*"'.
- Restrict IAM permissions for 'ecr:SetRepositoryPolicy' and 'ecr:PutRegistryPolicy' to a limited set of trusted administrators using least-privilege principles.
- Audit existing ECR policies to confirm that 'Principal: "*"' usage is intentional and restricted by 'Deny' statements or focused on read-only actions (pull-only).
- Use the provided investigation fields to identify the user identity, source IP, and user agent associated with any suspicious policy modifications.
