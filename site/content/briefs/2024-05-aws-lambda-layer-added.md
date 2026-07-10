---
title: AWS Lambda Layer Added to Existing Function
slug: 2024-05-aws-lambda-layer-added
description: Detection of a Lambda layer being added to an existing AWS Lambda function, potentially indicating malicious activity such as persistence, unauthorized code execution, or data interception by an attacker with the ability to modify function configurations.
date: "2024-05-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - lambda
  - execution
  - defense-evasion
vendors:
  - AWS
products:
  - AWS Lambda
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1648
    technique_name: Serverless Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
references:
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-persistence/aws-lambda-persistence/aws-lambda-layers-persistence
  - https://docs.aws.amazon.com/lambda/latest/api/API_PublishLayerVersion.html
  - https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionConfiguration.html
rules:
  - title: AWS Lambda Layer Added to Existing Function
    description: Detects when a Lambda layer is added to an existing AWS Lambda function, indicating potential malicious activity.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1578
      - T1578.005
      - T1648
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Lambda Publish Layer Version
    description: Detects when a Lambda Layer Version is published.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1578
      - T1578.005
      - T1648
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies when a Lambda layer is added to an existing AWS Lambda function. Lambda layers enable shared code, dependencies, or runtime modifications to be injected into a function’s execution environment. Threat actors with the ability to update function configurations may add a malicious layer to establish persistence, execute unauthorized code, or intercept data handled by the function. The activity is detected via CloudTrail logs that record `PublishLayerVersion*` or `UpdateFunctionConfiguration*` events. Reviewing these actions is important to ensure that all modifications are expected and authorized. This activity can be used for initial access, persistence and defense evasion.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account with sufficient permissions to modify Lambda function configurations.
2. The attacker identifies a target Lambda function to compromise.
3. The attacker creates a malicious Lambda layer containing malicious code or dependencies.
4. The attacker uses the `PublishLayerVersion` API call to publish the malicious layer to AWS.
5. The attacker uses the `UpdateFunctionConfiguration` API call to add the newly published layer to the target Lambda function's configuration.
6. The Lambda function is invoked, triggering the execution of the malicious code within the added layer.
7. The malicious code performs unauthorized actions, such as data exfiltration or establishing a reverse shell.

## Impact

Successful exploitation can lead to unauthorized code execution within the Lambda function's execution environment. This can compromise sensitive data, disrupt services, or establish persistence within the AWS environment. The modification of Lambda functions can be difficult to detect without proper monitoring.

## Recommendation

*   Deploy the Sigma rule "AWS Lambda Layer Added to Existing Function" to detect suspicious modifications to Lambda function configurations (see rules section).
*   Monitor AWS CloudTrail logs for `PublishLayerVersion*` and `UpdateFunctionConfiguration*` events to identify potentially malicious layer additions.
*   Implement strict IAM policies to limit the ability to modify Lambda function configurations and publish new layers.
*   Regularly review Lambda function configurations to ensure that all layers are authorized and legitimate.
*   Investigate any modifications to Lambda function configurations that do not align with approved changes or expected CI/CD behavior, referencing the investigation fields from the original source.
