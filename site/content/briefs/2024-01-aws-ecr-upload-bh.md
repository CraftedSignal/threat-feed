---
title: Suspicious AWS ECR Container Upload Outside Business Hours
slug: 2024-01-aws-ecr-upload-bh
description: An AWS Elastic Container Registry (ECR) container image upload occurring outside of normal business hours can indicate suspicious or malicious activity, such as an attacker attempting to deploy compromised containers.
date: "2024-01-02T12:00:00Z"
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
  - AWS Elastic Container Registry
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1587
    technique_name: Develop Capabilities
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_ecr_container_upload_outside_business_hours.yml
rules:
  - title: AWS ECR Container Upload Outside Business Hours
    description: Detects AWS ECR container image uploads occurring outside of normal business hours (e.g., 6 PM to 8 AM local time).
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1587.001
    data_sources:
      - cloudtrail
      - aws
  - title: AWS ECR Container Upload by Uncommon User Agent
    description: Detects AWS ECR container image uploads performed by a user agent that is not commonly associated with container deployments.
    platform: sigma
    severity: low
    tactics:
      - resource_development
    techniques:
      - T1587.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This alert focuses on detecting potentially malicious uploads to AWS Elastic Container Registry (ECR) that occur outside of typical business hours. While not inherently malicious, such activity can signify unauthorized access or insider threats attempting to deploy compromised container images. This detection is designed to identify anomalous behavior that warrants further investigation, especially in environments with strict container deployment policies. This detection uses the `aws_ecr_container_upload_outside_business_hours.yml` file from the Splunk security content repository.

## Attack Chain

1.  An attacker gains unauthorized access to AWS credentials through compromised credentials, exposed keys, or other means.
2.  The attacker uses these credentials to authenticate to the AWS environment.
3.  The attacker creates or modifies a Docker image to include malicious software, backdoors, or other unwanted components.
4.  The attacker uploads the malicious Docker image to an AWS ECR repository outside of normal business hours. This is done using the `docker push` command or AWS CLI.
5.  A deployment pipeline or manual deployment process pulls the newly uploaded (malicious) container image from ECR.
6.  The compromised container is deployed into a production or development environment.
7.  The malicious code within the container executes, potentially leading to data exfiltration, privilege escalation, or denial of service.

## Impact

A successful attack could lead to the deployment of compromised containers in the AWS environment. This can result in data breaches, service disruptions, or unauthorized access to sensitive resources. The impact is highly dependent on the nature of the malicious code injected into the container image. Early detection of unusual ECR upload activity outside business hours can help prevent or mitigate the impact of such attacks.
