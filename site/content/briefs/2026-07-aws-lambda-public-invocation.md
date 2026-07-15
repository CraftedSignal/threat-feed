---
title: AWS Lambda Function Policy Updated to Allow Public Invocation
slug: 2026-07-aws-lambda-public-invocation
description: Adversaries may modify AWS Lambda function policies via the AddPermission API call, setting the Principal to '*' to enable public invocation, which establishes persistence and creates a covert execution path within an AWS environment.
date: "2026-07-15T14:22:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloud
  - persistence
  - defense-evasion
  - cloudtrail
vendors:
  - AWS
products:
  - AWS Lambda
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Adversaries may abuse this configuration to establish persistence, create a covert execution path, or operate a function as an unauthenticated backdoor.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: Identifies when an AWS Lambda function policy is updated to allow public invocation. This rule detects use of the AddPermission API where the Principal is set to "*", enabling any AWS account to invoke the function.
    confidence_band: high
references:
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-persistence/aws-lambda-persistence
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-backdoor-function/
  - https://docs.aws.amazon.com/lambda/latest/api/API_AddPermission.html
rules:
  - title: AWS Lambda Function Policy Updated to Allow Public Invocation
    description: Detects when an AWS Lambda function policy is updated via AddPermission API call to allow public invocation by setting the 'Principal' to '*' for 'lambda:InvokeFunction'. This can be used by adversaries for persistence or creating a backdoor.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1546
      - T1578
      - T1578.005
    data_sources:
      - cloud
      - aws
rules_count: 1
---

Adversaries may exploit misconfigurations or compromised credentials within AWS environments to establish persistence and create unauthenticated backdoors. One such method involves modifying an AWS Lambda function's policy to allow public invocation. This is achieved by using the `AddPermission` API call and setting the `Principal` parameter to `"*"` for the `lambda:InvokeFunction` action. This modification allows any AWS account or service to invoke the targeted Lambda function, bypassing typical authentication and authorization mechanisms. This technique is particularly attractive to attackers as it creates a stealthy and persistent execution path, enabling them to trigger code execution at will without requiring further compromise of specific user credentials or access keys. Public invocation of Lambda functions is rarely a legitimate requirement outside of very specific use cases, making its unexpected appearance a strong indicator of malicious activity or significant misconfiguration.

## Attack Chain

1. **Initial Access**: An attacker obtains valid AWS credentials, possibly through phishing, leaked access keys, or compromise of an endpoint with AWS CLI configurations, gaining permissions to modify Lambda functions.
2. **Discovery**: The attacker enumerates existing AWS Lambda functions within the target environment, identifying functions that can be backdoored to maintain access or perform specific actions.
3. **Defense Evasion & Persistence**: The attacker utilizes the compromised credentials to make an `AddPermission` API call to the `lambda.amazonaws.com` service. The `request_parameters` for this call include the targeted `FunctionName`, an `Action` of `lambda:InvokeFunction`, and crucially, a `Principal` set to `"*"`. This action updates the Lambda function's resource policy, allowing it to be invoked by any AWS principal.
4. **Command and Control**: With the Lambda function now publicly invokable, the attacker can trigger its execution from an external, attacker-controlled AWS account or environment, establishing a persistent and unauthenticated C2 channel.
5. **Execution**: Upon invocation, the Lambda function executes with its associated IAM role, which may have permissions to access other AWS resources, interact with databases, or perform actions that further the adversary's objectives.
6. **Impact**: The attacker leverages the publicly invokable function to exfiltrate data, perform unauthorized modifications to cloud resources, or pivot to other services within the AWS environment, maintaining a foothold for extended periods.

## Impact

Successful exploitation of a publicly invokable Lambda function can lead to severe consequences, enabling unmonitored code execution and unauthorized access to sensitive internal resources. Attackers can leverage the function's associated IAM role to exfiltrate data, modify cloud infrastructure, or escalate privileges within the AWS environment. The unauthenticated nature of the invocation allows for persistent access that can be difficult to detect if proper logging and monitoring are not in place. The scope of impact depends on the permissions assigned to the Lambda function's execution role and the sensitivity of the data or resources it can access.

## Recommendation

* Deploy the Sigma rule "AWS Lambda Function Policy Updated to Allow Public Invocation" to your SIEM and tune for your environment to detect unauthorized policy modifications.
* Monitor CloudTrail logs for `AddPermission` events, especially those related to `lambda.amazonaws.com` and `lambda:InvokeFunction` actions, paying close attention to the `aws.cloudtrail.request_parameters` field for `principal=\\*`.
* Investigate the `aws.cloudtrail.user_identity.arn` associated with any suspicious `AddPermission` calls to identify the actor and determine if the activity is legitimate.
* Review and enforce least-privilege invocation policies for all Lambda functions to prevent unwarranted public access.
* Rotate or disable AWS credentials immediately if compromise is suspected, especially those used in detected malicious `AddPermission` API calls.
* Conduct a security review of any Lambda function found with public invocation permissions to ensure no misuse has occurred.
