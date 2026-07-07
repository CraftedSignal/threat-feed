---
title: AWS Lambda Event Source Mapping Abuse for Persistence and Data Exfiltration
slug: 2026-07-aws-lambda-event-source-mapping-persistence
description: Adversaries can exploit the creation of AWS Lambda event source mappings to establish stealthy persistence and execution, or to continuously siphon records from event sources like Amazon SQS, Kinesis, DynamoDB, MSK, Kafka, or MQ, by mapping an event source to an attacker-controlled Lambda function, enabling durable execution and data exfiltration without requiring further interactive access.
date: "2026-07-03T16:18:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - persistence
  - execution
  - data-exfiltration
vendors:
  - Amazon
  - Apache
products:
  - AWS Lambda
  - Amazon SQS
  - Amazon Kinesis
  - Amazon DynamoDB
  - Amazon MSK
  - Apache Kafka
  - Amazon MQ
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Adversaries with "lambda:CreateEventSourceMapping" permissions can abuse this to establish stealthy, event-driven persistence and execution
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1648
    technique_name: Serverless Execution
    evidence: Because the function then runs on its own whenever the source produces events, this grants durable execution without any further interactive activity by the adversary.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: Adversaries with "lambda:CreateEventSourceMapping" permissions can abuse this to establish stealthy, event-driven persistence and execution
    confidence_band: high
references:
  - https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventsourcemapping.html
  - https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html
rules:
  - title: AWS Lambda Event Source Mapping Creation
    description: Detects the successful creation of an AWS Lambda event source mapping, which adversaries can abuse for persistence or data exfiltration by automatically invoking malicious Lambda functions when new records arrive in event sources like SQS, Kinesis, or DynamoDB.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - persistence
    techniques:
      - T1546
      - T1578
      - T1578.005
      - T1648
    data_sources:
      - cloud
      - aws.cloudtrail
rules_count: 1
---

Adversaries possessing `lambda:CreateEventSourceMapping` permissions can abuse this AWS functionality to establish persistent access and facilitate data exfiltration within compromised AWS environments. This technique involves linking an event source, such as an Amazon SQS queue, Amazon Kinesis stream, DynamoDB stream, Amazon MSK, self-managed Apache Kafka topic, or Amazon MQ broker, to a malicious Lambda function. Once configured, the Lambda function is automatically invoked whenever new records arrive at the event source. This grants the attacker durable execution capabilities without requiring further interactive activity, allowing for continuous data siphoning or maintaining a foothold. This method offers a stealthy way to achieve persistence, as the event-driven nature can bypass traditional interactive session monitoring. This threat emphasizes the need for vigilant monitoring of Lambda configuration changes and strict permission management.

## Attack Chain

1.  **Initial Access**: An adversary gains initial access to an AWS account, potentially through compromised credentials or exploitation of a vulnerable application.
2.  **Privilege Escalation/Reconnaissance**: The adversary identifies or escalates privileges to a role with `lambda:CreateEventSourceMapping` permissions and `lambda:CreateFunction`/`lambda:UpdateFunctionCode` or similar permissions to deploy/modify Lambda functions.
3.  **Deploy Malicious Lambda Function**: The adversary deploys a new Lambda function or modifies an existing one to include malicious code designed for persistence or data exfiltration.
4.  **Identify Sensitive Event Source**: The adversary identifies an existing event source (e.g., an Amazon SQS queue, Kinesis stream, or DynamoDB stream) containing sensitive data or frequently processed events.
5.  **Create Event Source Mapping**: Using `lambda:CreateEventSourceMapping`, the adversary creates a mapping connecting the identified sensitive event source to their malicious Lambda function.
6.  **Event Triggered Execution**: As new records arrive in the event source, the malicious Lambda function is automatically invoked in the background.
7.  **Persistence/Data Exfiltration**: The malicious Lambda function executes, maintaining persistence by processing future events, or exfiltrating sensitive data from the event stream to an attacker-controlled destination.
8.  **Obfuscation**: The adversary may attempt to obscure the purpose of the mapping or blend it with legitimate system activity to avoid detection.

## Impact

Successful exploitation of this technique can lead to severe consequences, including continuous data exfiltration of sensitive information processed by the compromised AWS environment. For instance, if an SQS queue handling customer data or a Kinesis stream processing financial transactions is mapped, adversaries can silently siphon this data over an extended period. This method establishes a highly stealthy and durable persistence mechanism, making it difficult for defenders to detect and eradicate. The event-driven nature of Lambda functions also means the malicious code executes autonomously, requiring minimal further attacker interaction, thus reducing the chances of interactive C2 detection.

## Recommendation

*   Deploy the Sigma rule "AWS Lambda Event Source Mapping Creation" in this brief to your SIEM and tune for your environment to detect suspicious `CreateEventSourceMapping` calls.
*   Restrict `lambda:CreateEventSourceMapping` permissions to only trusted roles and automated deployment pipelines, referencing the AWS documentation on API permissions.
*   Investigate all alerts from the "AWS Lambda Event Source Mapping Creation" rule, paying close attention to `aws.cloudtrail.user_identity.arn`, `functionName`, and `eventSourceArn` to determine legitimacy.
*   Regularly audit existing AWS Lambda event source mappings to identify any unauthorized or suspicious configurations, focusing on the target function and event source involved.
