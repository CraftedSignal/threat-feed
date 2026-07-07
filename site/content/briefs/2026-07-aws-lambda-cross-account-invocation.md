---
title: AWS Lambda Function Invoked Cross-Account
slug: 2026-07-aws-lambda-cross-account-invocation
description: Adversaries leverage cross-account access to invoke AWS Lambda functions from a different account than the function owner, enabling code execution or data retrieval, which requires AWS Lambda data event logging to detect.
date: "2026-07-03T15:55:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - aws-lambda
  - execution
  - cloud-security
vendors:
  - AWS
products:
  - AWS Lambda
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1648
    technique_name: Serverless Execution
    evidence: Identifies an AWS Lambda function invoked by a principal whose AWS account differs from the account that owns the function (a cross-account invocation).
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/execution_lambda_function_invoked_cross_account.toml
  - https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html
  - https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html
---

This brief details a detection for cross-account AWS Lambda function invocations. Adversaries may leverage previously granted invoke permissions on a Lambda function, or operate from a separate attacker-controlled AWS account, to execute functions in a victim's environment. This activity, often a data-plane realization of an earlier cross-account resource-policy grant, allows an attacker to execute arbitrary code or retrieve sensitive data controlled by the function. The detection relies on capturing AWS Lambda data events through CloudTrail, which is not enabled by default, and identifying discrepancies between the invoking principal's account ARN (`aws.cloudtrail.user_identity.arn`) and the invoked function's owning account ARN (`aws.cloudtrail.request_parameters`). This behavior, while potentially legitimate in multi-account architectures, warrants investigation when observed.

## Attack Chain

1. An adversary gains control over an AWS account or secures `lambda:InvokeFunction` permissions for a target Lambda function in a different AWS account.
2. The adversary initiates an `Invoke` API call to the target Lambda function from their external or controlled AWS account.
3. The AWS Lambda service processes the cross-account invocation request, authenticating the invoking principal.
4. The invoked Lambda function executes, performing its defined operations within the victim's AWS environment.
5. AWS CloudTrail logs the successful `Invoke` data event, including the ARN of the invoking principal and the ARN of the function.
6. The adversary potentially receives the function's output, allowing for data retrieval, or benefits from actions performed by the function, such as resource manipulation or further compromise.

## Impact

If an unauthorized cross-account Lambda invocation succeeds, adversaries can execute arbitrary code within the context of the Lambda function's permissions, potentially leading to privilege escalation, data exfiltration from resources accessible by the function, or unauthorized modification of the victim's AWS environment. This can result in significant data breaches, service disruption, or complete compromise of the affected AWS account. While this activity can be legitimate in multi-account environments, unauthorized instances represent a critical security breach impacting data confidentiality, integrity, and availability.

## Recommendation

* Enable AWS Lambda data event logging in CloudTrail, as described in the `setup` section of the source rule, to ensure the necessary telemetry is captured for this detection.
* Implement the detection logic outlined in the provided Elastic rule within your SIEM to identify cross-account Lambda function invocations.
* When an alert triggers, review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.request_parameters` fields to determine the caller and function accounts, validating against known, trusted cross-account access.
* Investigate recent activity from the `Esql.caller_account` and `Esql.source_ips` identified by the detection for other suspicious cross-account actions.
* If an unauthorized cross-account invocation is confirmed, promptly remove the `lambda:InvokeFunction` permissions using `RemovePermission` and review what the function accessed or returned, as suggested in the `response and remediation` section of the source.
