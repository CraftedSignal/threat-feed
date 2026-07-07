---
title: AWS Lambda Function URL Created with Public Access
slug: 2026-07-aws-lambda-function-url-public-access
description: Adversaries may establish a persistent, internet-reachable entry point by creating or updating an AWS Lambda function URL with an authentication type of NONE, allowing unauthenticated invocation for command and control, data exfiltration, or on-demand code execution, thereby bypassing the need for valid AWS credentials.
date: "2026-07-03T16:15:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - persistence
  - defense-evasion
vendors:
  - Amazon
products:
  - AWS Lambda
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Adversaries can use a public function URL to establish a durable, internet-reachable entry point for command and control, data egress, or on-demand execution of attacker-controlled code.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: Identifies the creation or update of an AWS Lambda function URL configured with an authentication type of NONE.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: bypassing the need for valid AWS credentials to invoke the function.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/lambda/latest/dg/lambda-urls.html
  - https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html
rules:
  - title: AWS Lambda Function URL Created or Updated with Public Access
    description: Detects the creation or update of an AWS Lambda function URL configured with `authType=NONE`, exposing it to unauthenticated public internet invocation, which can be used for persistence or defense evasion.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1133
      - T1578.005
    data_sources:
      - cloudtrail
      - aws
rules_count: 1
---

This threat involves the misconfiguration of AWS Lambda function URLs, allowing adversaries to establish a persistent and publicly accessible foothold within a compromised AWS environment. Specifically, the creation or modification of a Lambda function URL with `authType=NONE` exposes the function to unauthenticated invocation directly from the internet. This technique enables attackers to bypass traditional AWS credential requirements for function execution, creating a durable entry point for various malicious activities. Such public URLs can serve as covert command and control (C2) channels, facilitate unauthorized data exfiltration, or provide an on-demand platform for executing arbitrary attacker-controlled code. This configuration is typically rare for legitimate applications and warrants immediate review due to the significant security implications of exposing compute resources to the public internet without authentication.

## Attack Chain

1.  An adversary gains initial access to an AWS account, potentially via compromised credentials or an exploited vulnerability.
2.  Using the compromised credentials, the adversary invokes the `CreateFunctionUrlConfig` or `UpdateFunctionUrlConfig` API call against an existing or new AWS Lambda function.
3.  Within this API call, the adversary intentionally sets the `AuthType` parameter to `NONE`.
4.  This action successfully configures the target AWS Lambda function with a unique, publicly accessible HTTPS endpoint (Function URL).
5.  The adversary can then directly invoke this Lambda function from any internet-connected system without providing any AWS authentication credentials.
6.  This publicly exposed function serves as a persistent and unauthenticated entry point, enabling command and control (C2) operations.
7.  The adversary can leverage this for unauthorized data exfiltration by programming the Lambda function to send sensitive data to an external location.
8.  Alternatively, the Lambda function can be used to execute arbitrary attacker-controlled code on demand within the AWS environment, maintaining a durable backdoor into the system.

## Impact

The successful exploitation of this misconfiguration grants adversaries a persistent and unauthenticated entry point into the compromised AWS environment. This can lead to a range of severe consequences, including full compromise of the affected Lambda function's execution role, leading to lateral movement, privilege escalation, and access to other AWS resources. Attackers can use this persistent access for command and control, unauthorized data exfiltration of sensitive information (e.g., customer data, intellectual property), or to launch further attacks and maintain a foothold. The exact number of victims is not specified, but any organization utilizing AWS Lambda functions is potentially vulnerable if access to credentials allows this misconfiguration.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect suspicious `CreateFunctionUrlConfig` or `UpdateFunctionUrlConfig` events with `authType=NONE` in your AWS CloudTrail logs.
*   Investigate the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.type` fields for any detections to identify the principal responsible for the change.
*   Review the `aws.cloudtrail.request_parameters` for the `functionName` and the `authType`, and `aws.cloudtrail.response_elements` for the resulting `functionUrl` for unauthorized public exposures.
*   If an unauthorized public URL is identified, immediately change the function URL `authType` to `AWS_IAM` or delete the function URL configuration as detailed in the AWS documentation linked in this brief.
*   Review the function's code, execution role, and recent changes (e.g., `UpdateFunctionCode`, `UpdateFunctionConfiguration`) for signs of tampering following detection.
*   Restrict `lambda:CreateFunctionUrlConfig` and `lambda:UpdateFunctionUrlConfig` permissions to only trusted roles within your AWS environment to prevent unauthorized creation of public function URLs.
