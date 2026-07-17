---
title: AWS Potential Cryptomining via ECS Task Definition Deployment
slug: 2026-07-aws-ecs-cryptomining
description: Adversaries, after compromising AWS credentials, deploy cryptomining operations on Amazon ECS and AWS Fargate by registering task definitions with public high-CPU container images and then launching them, leading to unauthorized resource consumption and increased cloud costs.
date: "2026-07-17T06:44:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - cryptomining
  - resource-hijacking
  - ecs
  - fargate
vendors:
  - Amazon
products:
  - Amazon ECS
  - AWS Fargate
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
    evidence: 'a common impact action is to abuse ECS/Fargate for cryptomining: the adversary registers a task definition pointing at a public miner image... at maximum CPU to maximize hashrate, then launches it at scale'
    confidence_band: high
references:
  - https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-ecs-crypto-mining/
  - https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definitions.html
iocs:
  - type: domain
    value: docker.io
  - type: domain
    value: index.docker.io
  - type: domain
    value: ghcr.io
  - type: domain
    value: quay.io
  - type: domain
    value: public.ecr.aws
ioc_counts:
  domain: 5
---

This threat involves threat actors exploiting compromised AWS credentials to conduct cryptomining activities within Amazon ECS and AWS Fargate environments. This attack typically unfolds when an adversary gains unauthorized access to an AWS account. They then register an Amazon ECS task definition that references a public container image (e.g., from Docker Hub, GitHub Container Registry, Quay, or AWS ECR Public) configured for maximum CPU allocation, specifically 8 or 16 vCPU, to maximize hashrate. Following the task definition registration, the same compromised principal launches ECS workloads using API calls such as `RunTask`, `StartTask`, or `CreateService`. This pattern, correlating both the registration of a high-compute public image and its subsequent deployment by the same identity, is a strong indicator of active cryptomining operations, distinguishing it from potentially benign standalone task registrations and significantly reducing false positives.

## Attack Chain

1. Adversary compromises AWS credentials (e.g., through phishing, exposed access keys, or vulnerable applications).
2. Using the compromised credentials, the adversary gains unauthorized access to the AWS environment, often targeting ECS/Fargate.
3. The adversary registers a new Amazon ECS task definition by invoking the `RegisterTaskDefinition` API.
4. The registered task definition specifies a container image hosted on a public repository (e.g., `docker.io`, `ghcr.io`, `quay.io`, or `public.ecr.aws`) which contains cryptomining software.
5. The task definition is configured to request a high CPU allocation (8192 units for 8 vCPU or 16384 units for 16 vCPU) to maximize cryptomining efficiency.
6. The adversary subsequently launches ECS workloads, services, or tasks based on this malicious task definition using API calls such as `RunTask`, `StartTask`, or `CreateService`.
7. The newly launched ECS tasks or services begin executing the cryptomining software, consuming significant AWS compute resources in the compromised account.
8. The attacker benefits from the unauthorized use of cloud resources for cryptocurrency generation, while the victim incurs unexpected cloud costs and potential service degradation.

## Impact

Successful exploitation results in significant financial impact for the victim organization due to unauthorized and excessive consumption of AWS compute resources. Cryptomining operations, especially those configured for high CPU usage on services like Amazon ECS and Fargate, can lead to unexpectedly high cloud bills. Beyond direct costs, the resource hijacking can degrade the performance of legitimate services running on the same AWS account or impact overall cloud resource availability. This attack pattern signifies a credential compromise, which can lead to further unauthorized activities, data exfiltration, or persistence within the cloud environment if not promptly addressed.

## Recommendation

* Monitor AWS CloudTrail logs for `RegisterTaskDefinition` events where `request_parameters` indicate a public container image source (e.g., `docker.io`, `ghcr.io`, `quay.io`, `public.ecr.aws`) and a high CPU allocation (`8192` or `16384`).
* Monitor AWS CloudTrail logs for `RunTask`, `StartTask`, or `CreateService` events that follow a suspicious `RegisterTaskDefinition` by the same principal (`aws.cloudtrail.user_identity.arn`).
* Review the `aws.cloudtrail.request_parameters` in `RegisterTaskDefinition` events to identify the specific container image and CPU settings.
* Investigate the `aws.cloudtrail.user_identity.arn` and associated `source.ip` for any identified suspicious events to determine if the principal is legitimate or compromised.
* Implement AWS IAM policies that restrict the ability to register task definitions to only use approved private ECR repositories and limit the CPU allocation for tasks where appropriate.
* Block the IOCs listed at the network perimeter or within AWS Network ACLs and Security Groups to prevent outbound connections to known cryptomining pools if observed.
