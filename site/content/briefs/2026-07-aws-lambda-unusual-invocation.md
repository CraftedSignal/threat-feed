---
title: AWS Lambda Function Invoked by Unusual Principal
slug: 2026-07-aws-lambda-unusual-invocation
description: Detects the first direct invocation of an AWS Lambda function by a principal within a 14-day period, excluding AWS service invocations, which can indicate adversary lateral movement, credential abuse, or unauthorized data retrieval in AWS environments.
date: "2026-07-03T15:59:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - lambda
  - execution
  - lateral-movement
vendors:
  - Amazon
products:
  - AWS Lambda
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1648
    technique_name: Serverless Execution
    evidence: Adversaries who compromise credentials or move laterally may directly invoke functions to execute code, retrieve data returned by a function, or abuse an over-permissioned execution role. Direct, ad hoc invocation by a principal that does not normally call Lambda deviates from the usual event-driven invocation pattern and is worth reviewing.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/execution_lambda_function_invoked_by_unusual_principal.toml
  - https://docs.aws.amazon.com/lambda/latest/api/API_Invoke.html
  - https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html
rules:
  - title: AWS Lambda Direct Invocation by Principal
    description: Detects direct invocation of an AWS Lambda function by a principal (user/role) that is not an AWS service. This activity, especially when it's the first time for a given principal in an account (as per original Elastic rule logic), can indicate credential compromise, lateral movement, or unauthorized access. Requires AWS Lambda data event logging in CloudTrail.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1648
    data_sources:
      - security_control_log
      - aws.cloudtrail
rules_count: 1
---

This brief addresses a detection mechanism designed to identify suspicious activity within Amazon Web Services (AWS) environments, specifically targeting the AWS Lambda service. Adversaries who successfully compromise credentials or achieve lateral movement within an AWS account may attempt to directly invoke Lambda functions to execute their code, retrieve sensitive data, or exploit over-permissioned execution roles. This detection focuses on such direct invocations made by a principal (user, role, or assumed role) that deviates from typical event-driven patterns and represents the first such action by that specific principal within the last 14 days. This behavior often signals credential abuse or unauthorized access and is a critical indicator for defenders to review. Effective detection requires enabling AWS Lambda data event logging in CloudTrail, which is not configured by default.

## Attack Chain

1.  **Initial Access**: An adversary obtains legitimate AWS credentials, often through methods such as phishing, exploiting vulnerable web applications to discover API keys, or compromising an endpoint with AWS CLI configurations.
2.  **Lateral Movement**: The adversary uses the initially compromised credentials to pivot within the AWS environment, assuming roles or gaining access to other credentials that possess `lambda:InvokeFunction` permissions for target Lambda functions.
3.  **Credential Usage**: The adversary utilizes these newly acquired or validated credentials to interact directly with AWS services, bypassing typical event-driven automation for Lambda functions.
4.  **Execution via Lambda**: The adversary directly invokes an AWS Lambda function using tools like the AWS CLI, SDK, or management console, an action recorded as an `Invoke` API call in CloudTrail. This specific invocation marks the first time this particular principal has directly called a Lambda function in the account within a rolling 14-day window.
5.  **Malicious Payload Execution**: The invoked Lambda function, under adversary control or via its compromised execution context, executes malicious code, performs reconnaissance, or triggers unintended actions within the serverless environment.
6.  **Objective Achievement**: The adversary uses the Lambda function's capabilities to exfiltrate sensitive data, establish persistence, further elevate privileges, or perform other actions to achieve their ultimate objective.

## Impact

The successful exploitation of Lambda function invocation can lead to severe consequences, including unauthorized code execution, sensitive data exfiltration, and privilege escalation within the AWS environment. Depending on the Lambda function's permissions and access, adversaries could gain control over other AWS resources, modify infrastructure, or compromise critical applications and databases. This type of compromise can result in significant financial losses, reputational damage, and regulatory non-compliance, particularly if the functions handle personal identifiable information (PII) or other regulated data.

## Recommendation

*   Enable AWS Lambda data event logging in CloudTrail for all relevant functions, especially those handling sensitive data or possessing broad permissions, as this is required to detect the activity described in the rule.
*   Deploy the provided Sigma rule to your SIEM and tune it to identify direct Lambda invocations that deviate from known legitimate operational or testing activities.
*   When an alert triggers, review the `aws.cloudtrail.user_identity.arn`, `source.ip`, and `user_agent.original` fields to identify the invoking principal and source of the activity.
*   Inspect `aws.cloudtrail.request_parameters` to determine the specific `functionName` that was invoked and assess its criticality and owner.
*   If unauthorized activity is confirmed, promptly rotate or restrict the credentials associated with the `aws.cloudtrail.user_identity.arn` that triggered the alert.
*   Constrain `lambda:InvokeFunction` permissions to only the identities and services that explicitly require them, following the principle of least privilege.
