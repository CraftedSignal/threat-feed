---
title: Sensitive Data Exposure in AWS Bedrock Claude Prompts
slug: 2026-07-aws-bedrock-claude-sensitive-data
description: This detection identifies instances where sensitive data, including social security numbers, passwords, API keys, and credit card numbers, is inadvertently or maliciously sent within prompts to AWS Bedrock Claude AI models, indicating potential data loss, credential leakage, or insider threat activity.
date: "2026-07-07T08:16:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - bedrock
  - claude
  - data-exposure
  - insider-threat
  - cloud
  - application
  - anomaly
vendors:
  - AWS
products:
  - AWS Bedrock Claude
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Exposure of sensitive data through AI prompts may indicate data loss, credential leakage, or insider threat activity.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This detection identifies sensitive data such as social security numbers, passwords, API keys, and credit card numbers being sent in prompts to AWS Bedrock Claude models. Exposure of sensitive data through AI prompts may indicate data loss, credential leakage, or insider threat activity.
    confidence_band: high
references:
  - https://aws.amazon.com/blogs/apn/unlocking-the-power-of-splunk-with-amazon-bedrock-an-agentic-ai-approach-to-build-customized-splunk-assistants-using-bedrock-agents/
  - https://help.splunk.com/en/splunk-observability-cloud/observability-for-ai/splunk-ai-infrastructure-monitoring/set-up-ai-infrastructure-monitoring/amazon-bedrock
  - https://research.splunk.com/stories/aws_bedrock_security/
  - https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
rules:
  - title: Detect Sensitive Data in AWS Bedrock Claude Prompts
    description: Detects sensitive data such as AWS keys, GitHub tokens, Slack tokens, Stripe keys, OpenAI keys, Google API keys, private keys, generic passwords, bearer tokens, Social Security Numbers (SSNs), and credit card numbers being sent in prompts to AWS Bedrock Claude models. This indicates potential data leakage or insider threat.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - exfiltration
    techniques:
      - T1552
      - T1567
    data_sources:
      - cloud
      - aws.bedrock
rules_count: 1
---

This threat brief focuses on the exposure of sensitive data within prompts submitted to Amazon Web Services (AWS) Bedrock Claude large language models. This detection, first published on July 6, 2026, aims to identify scenarios where confidential information such as AWS Access Keys, GitHub Personal Access Tokens, Slack tokens, Stripe keys, OpenAI keys, Google API keys, private key headers, generic passwords, bearer tokens, Social Security Numbers (SSNs), or credit card numbers are transmitted as part of AI model input. Such occurrences signal potential data loss, credential compromise, or insider threat activity, as the sensitive data becomes logged and potentially accessible to unauthorized individuals or systems with access to Bedrock model invocation logs. Organizations using AWS Bedrock Claude models are targeted, with the risk arising from misconfiguration, user error, or malicious intent.

## Attack Chain

1.  An authorized user or application constructs an input prompt for an AWS Bedrock Claude model.
2.  The prompt inadvertently, due to user error, or maliciously, due to an insider threat, includes sensitive information such as API keys, passwords, SSNs, or credit card numbers.
3.  The user or application invokes the AWS Bedrock API to send this prompt to the designated Claude model.
4.  The AWS Bedrock service processes the prompt, and if model invocation logging is enabled, the complete prompt content, including the sensitive data, is recorded.
5.  These logs are typically stored in AWS S3 buckets or CloudWatch Logs, making the sensitive data discoverable and accessible to anyone with appropriate permissions to these log storage locations.
6.  The exposure of this sensitive data in logs can lead to data loss, compliance violations, or credential compromise if the logs are accessed by unauthorized entities, either internally or externally, ultimately facilitating further malicious activities like account takeover or data exfiltration.

## Impact

The primary impact of sensitive data exposure in AI prompts is the potential for significant data loss and credential compromise. If API keys, passwords, or PII like SSNs and credit card numbers are logged, they become vulnerable to unauthorized access. This can lead to account takeovers, unauthorized access to systems and data, financial fraud, and severe breaches of privacy regulations (e.g., GDPR, HIPAA). While no specific victim count is available, any organization utilizing AWS Bedrock Claude without stringent data handling policies and monitoring is susceptible to this risk. Such incidents can also result in reputational damage and substantial regulatory fines.

## Recommendation

*   Enable Amazon Bedrock model invocation logging as described in the AWS documentation (refer to `https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html`).
*   Ingest AWS Bedrock Claude model invocation logs into your Security Information and Event Management (SIEM) platform for analysis and alerting, ensuring the `aws_bedrock_claude_sensitive_data_in_prompts` rule can process them.
*   Deploy the `Detect Sensitive Data in AWS Bedrock Claude Prompts` Sigma rule to your SIEM and tune it for your environment.
*   Implement data loss prevention (DLP) policies and controls at endpoints and network egress points to prevent sensitive data from entering AI prompts.
*   Review detections generated by this rule, as described in the `falsepositives` section, to differentiate between legitimate test data and actual sensitive data exposure.
