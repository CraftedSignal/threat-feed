---
title: Potential Cross-Region Inference Abuse in AWS Bedrock Claude
slug: 2026-07-aws-bedrock-claude-cross-region-abuse
description: This threat brief details the potential for malicious actors to exploit AWS Bedrock Claude models by performing cross-region inference with high input token counts, indicating attempts to bypass regional restrictions, exfiltrate sensitive data, or conduct unauthorized actions across different AWS regions.
date: "2026-07-07T08:09:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - inference-abuse
  - data-exfiltration
  - defense-evasion
vendors:
  - AWS
products:
  - AWS Bedrock Claude
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: Cross-region inference abuse may indicate attempts to bypass regional restrictions, exfiltrate data, or perform unauthorized actions across different AWS regions.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Cross-region inference abuse may indicate attempts to bypass regional restrictions, exfiltrate data, or perform unauthorized actions across different AWS regions.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1599
    technique_name: Application Layer Protocol
    evidence: This detection identifies potential cross-region inference abuse in AWS Bedrock Claude models... using model invocation logging.
    confidence_band: med
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/aws_bedrock_claude_cross_region_possible_inference_abuse.yml
  - https://aws.amazon.com/blogs/apn/unlocking-the-power-of-splunk-with-amazon-bedrock-an-agentic-ai-approach-to-build-customized-splunk-assistants-using-bedrock-agents/
  - https://help.splunk.com/en/splunk-observability-cloud/observability-for-ai/splunk-ai-infrastructure-monitoring/set-up-ai-infrastructure-monitoring/amazon-bedrock
  - https://research.splunk.com/stories/aws_bedrock_security/
  - https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
rules:
  - title: AWS Bedrock Claude Possible Cross-Region Inference Abuse (High Tokens)
    description: Detects potential cross-region inference abuse in AWS Bedrock Claude models by identifying invocations with high input token counts (>=2000) where the 'region' and 'inferenceRegion' fields are present. This rule flags high-volume Bedrock activity; a critical next step for detection engineers is to correlate these events and filter for instances where 'region' is NOT equal to 'inferenceRegion' in their SIEM, as direct field comparison is not standard Sigma.
    platform: sigma
    severity: high
    tactics:
      - collection
      - defense_evasion
      - exfiltration
    techniques:
      - T1041
      - T1562
      - T1599
    data_sources:
      - application
      - aws_bedrock
rules_count: 1
---

Malicious actors may be exploiting AWS Bedrock Claude models to perform cross-region inference abuse, a technique that allows them to bypass regional data residency policies and exfiltrate sensitive information. This activity is detected when a user or compromised entity invokes an Amazon Bedrock Claude model from a different AWS region than the one where the request originated, particularly when accompanied by a high volume of input tokens (e.g., 2000 or more). This method could be used to process and extract confidential data from a region with strict residency requirements by sending it to a model hosted in a more permissive region. The detection, first published in July 2026, aims to identify these unusual inference patterns that could signify unauthorized data movement or policy evasion.

## Attack Chain

1.  **Initial Access**: An attacker gains unauthorized access to an AWS account, potentially through compromised credentials, API keys, or an exploited EC2 instance with Bedrock permissions.
2.  **Reconnaissance/Environment Setup**: The attacker identifies available AWS regions and the presence of AWS Bedrock services within the target account.
3.  **Cross-Region Session Establishment**: The attacker establishes an authenticated session in an AWS region (e.g., `us-east-1`) where the compromised credentials are valid or the source data resides.
4.  **Bedrock Model Invocation (Cross-Region)**: The attacker then invokes an AWS Bedrock Claude model, but explicitly specifies an `inferenceRegion` (e.g., `eu-west-1`) that is different from the originating `region` of their current session.
5.  **Sensitive Data Injection**: The attacker feeds a large volume of sensitive or proprietary data (indicated by high `input.inputTokenCount`) into the Bedrock Claude model for processing, analysis, or summarization.
6.  **Data Exfiltration/Bypass**: The model processes the input, and the resulting output (potentially summarized or reformulated sensitive data) is returned to the attacker's control, effectively bypassing regional data residency policies or exfiltrating information.
7.  **Post-Exploitation/Cleanup**: The attacker may delete logs, modify permissions, or continue to leverage the cross-region inference for further unauthorized activities or to maintain persistence.

## Impact

If cross-region inference abuse in AWS Bedrock Claude models goes undetected, organizations face severe risks, including the potential for significant data exfiltration, violation of data residency regulations (e.g., GDPR, HIPAA), and unauthorized access to intellectual property. This can lead to substantial financial penalties, reputational damage, and loss of competitive advantage. While no specific victim counts are available, any organization utilizing AWS Bedrock with sensitive data, especially those operating under strict regional compliance, is a potential target. The successful exfiltration of data through this method can be difficult to trace as it leverages legitimate cloud services.

## Recommendation

*   **Enable Bedrock Invocation Logging**: Immediately enable Amazon Bedrock model invocation logging for all Claude models in AWS, ensuring request/response payloads are delivered to S3 and/or CloudWatch Logs as detailed in the AWS documentation (https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html).
*   **Ingest Logs to SIEM**: Configure the Splunk Add-on for AWS (https://splunkbase.splunk.com/app/1876) or equivalent SIEM logging to ingest AWS Bedrock model invocation logs into your security information and event management (SIEM) platform.
*   **Deploy and Tune Detection Rule**: Deploy the `AWS Bedrock Claude Possible Cross-Region Inference Abuse (High Tokens)` Sigma rule or its equivalent logic to your SIEM. Tune the `input.inputTokenCount` threshold for your environment and ensure correlation logic is implemented to identify events where `region` is not equal to `inferenceRegion`.
*   **Investigate Alerts**: Establish a robust incident response process to promptly investigate all alerts generated by the `AWS Bedrock Claude Possible Cross-Region Inference Abuse (High Tokens)` detection, prioritizing those with a clear `region != inferenceRegion` mismatch.
