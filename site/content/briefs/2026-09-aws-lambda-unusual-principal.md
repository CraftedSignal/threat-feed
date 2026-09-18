---
title: Detection of Anomalous Direct AWS Lambda Function Invocations
slug: 2026-09-aws-lambda-unusual-principal
description: This threat brief details the risk of unauthorized or lateral movement via direct AWS Lambda function invocation by non-standard principals, highlighting detection methodologies for cloud environments.
date: "2026-09-18T19:30:13Z"
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
vendors:
  - Amazon
products:
  - AWS Lambda
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1648
    technique_name: Serverless Execution
    evidence: Adversaries who compromise credentials or move laterally may directly invoke functions to execute code, retrieve data returned by a function, or abuse an over-permissioned execution role.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/lambda/latest/api/API_Invoke.html
  - https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/execution_lambda_function_invoked_by_unusual_principal.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable data event logging for AWS Lambda in CloudTrail to gain visibility into Invoke actions.
      owner: IT Operations
      due: 72h
      evidence: This rule relies on AWS Lambda data event logging, which is not enabled by default.
  hunt_leads:
    - lead: Identify all principals that have invoked Lambda functions directly in the last 30 days.
      technique_id: T1648
      data_needed:
        - CloudTrail data events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Direct, ad hoc invocation by a principal that does not normally call Lambda deviates from the usual event-driven invocation pattern.
---

Adversaries who obtain cloud credentials may perform direct invocations of AWS Lambda functions to execute code, exfiltrate data, or move laterally within an AWS account. Unlike standard event-driven invocations triggered by AWS services (such as S3 or EventBridge), which are excluded from this detection pattern, direct invocations via the CLI, SDK, or management console are rare and often indicate reconnaissance or exploitation. This behavior is significant because Lambda functions frequently operate with over-permissioned execution roles, providing attackers an avenue to interact with other cloud services. Defenders should monitor for direct 'Invoke' calls from principals that do not typically interact with the Lambda service to identify potential credential abuse or unauthorized ad-hoc execution. This detection relies on AWS CloudTrail data-plane logging, which must be explicitly enabled for Lambda, as it is not active by default.

## Impact

Successful abuse of Lambda functions can lead to unauthorized data retrieval, sensitive code execution, and escalation of privileges through inherited IAM roles. Organizations may face significant data exposure if functions process sensitive information, or attackers may use functions as a launchpad for further internal cloud resource compromise.

## Recommendation

* Enable AWS CloudTrail data event logging specifically for Lambda functions to ensure the 'Invoke' action is recorded.
* Implement the provided detection logic in your SIEM to monitor for 'Invoke' calls from identities that lack a historical record of such activity in the past 14 days.
* Review CloudTrail logs for unexpected usage of Lambda APIs by newly created or rarely used IAM roles and access keys.
* Constrain 'lambda:InvokeFunction' permissions using IAM policies to adhere to the principle of least privilege, restricting access to only necessary automated services and specific human operators.
