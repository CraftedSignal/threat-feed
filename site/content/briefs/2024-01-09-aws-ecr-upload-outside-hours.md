---
title: AWS ECR Container Upload Outside Business Hours
slug: 2024-01-09-aws-ecr-upload-outside-hours
description: This analytic detects the upload of a new container image to AWS Elastic Container Registry (ECR) outside of standard business hours, indicating potential unauthorized activity and leveraging AWS CloudTrail logs to identify `PutImage` events during non-business hours.
date: "2024-01-09T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - ecr
  - container
vendors:
  - AWS
products:
  - Elastic Container Registry
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://attack.mitre.org/techniques/T1204/003/
rules:
  - title: Detect AWS ECR Container Upload Outside Business Hours
    description: Detects container uploads to AWS Elastic Container Registry (ECR) outside of standard business hours (8 PM to 8 AM or weekends) using AWS CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.003
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS ECR PutImage Event
    description: Detects any PutImage event in AWS Elastic Container Registry (ECR), regardless of the time.  This provides a baseline for monitoring container image uploads.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    techniques:
      - T1070
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection focuses on identifying anomalous container image uploads to AWS Elastic Container Registry (ECR). Specifically, it flags `PutImage` events logged in AWS CloudTrail that occur outside of typical business hours (between 8 PM and 8 AM, or on weekends). The detection aims to uncover potentially malicious activity such as unauthorized uploads from compromised accounts or insider threats. The version of the Splunk detection being used is 11, published on 2026-04-15. Successful exploitation could result in the deployment of unauthorized or malicious containers, potentially leading to data breaches, service disruptions, or supply chain compromise. Defenders should investigate any detected activity promptly to validate its legitimacy and prevent further malicious actions. The scope includes all AWS accounts utilizing ECR.

## Attack Chain

1.  An attacker gains unauthorized access to an AWS account, potentially through compromised credentials or a misconfigured IAM role.
2.  The attacker leverages the AWS CLI or SDK to interact with the ECR service.
3.  The attacker authenticates to ECR using the compromised credentials or assumed role.
4.  The attacker builds or obtains a malicious container image.
5.  The attacker uses the `aws ecr get-login-password` command to retrieve an authentication token for Docker.
6.  The attacker authenticates Docker to the ECR registry using the retrieved token.
7.  The attacker executes a `docker push` command to upload the malicious container image to a target ECR repository using the `PutImage` API call. This occurs outside of normal business hours.
8.  The malicious container image is subsequently deployed within the AWS environment, leading to code execution and further compromise.

## Impact

A successful attack could allow an attacker to deploy unauthorized or malicious containers within the AWS environment. This can lead to data breaches, service disruptions, or the injection of malicious code into production systems. The number of affected organizations and the extent of the damage are dependent on the attacker's objectives and the security posture of the targeted AWS environment. The sectors most at risk are those heavily reliant on containerized applications, such as software development, financial services, and e-commerce.

## Recommendation

*   Deploy the Sigma rule `Detect AWS ECR Container Upload Outside Business Hours` to your SIEM and tune for your environment.
*   Investigate any `PutImage` events flagged by the detection during non-business hours, focusing on the user identified by the `user` field in the logs.
*   Review IAM policies associated with the user identified in the logs, ensuring they adhere to the principle of least privilege.
*   Monitor AWS CloudTrail logs for suspicious activity related to container image uploads, using the `data_source` field as a reference.
*   Implement multi-factor authentication (MFA) for all AWS accounts and IAM users to mitigate the risk of credential compromise.
*   Review and update container image security policies to prevent the deployment of unauthorized or vulnerable images.
