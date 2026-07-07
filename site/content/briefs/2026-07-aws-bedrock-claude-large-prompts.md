---
title: Detection of Unusually Large Prompts in AWS Bedrock Claude
slug: 2026-07-aws-bedrock-claude-large-prompts
description: This brief describes how to detect unusually large prompts sent to AWS Bedrock Claude models, which may indicate prompt injection attacks, data exfiltration attempts, or abuse of the AI service, through statistical baselining or high static thresholds.
date: "2026-07-07T08:18:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - ai-security
  - prompt-injection
  - data-exfiltration
  - anomaly-detection
  - cloud
vendors:
  - Amazon Web Services
products:
  - AWS Bedrock Claude
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1560
    technique_name: Archive Collected Data
    evidence: Abnormally large prompts may indicate prompt injection attacks
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Abnormally large prompts may indicate ... data exfiltration attempts
    confidence_band: high
references:
  - https://aws.amazon.com/blogs/apn/unlocking-the-power-of-splunk-with-amazon-bedrock-an-agentic-ai-approach-to-build-customized-splunk-assistants-using-bedrock-agents/
  - https://help.splunk.com/en/splunk-observability-cloud/observability-for-ai/splunk-ai-infrastructure-monitoring/set-up-ai-infrastructure-monitoring/amazon-bedrock
  - https://research.splunk.com/stories/aws_bedrock_security/
  - https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
rules:
  - title: Detect Large Prompts in AWS Bedrock Claude
    description: Detects AWS Bedrock Claude invocation requests with an input token count exceeding a specified large threshold. While the source Splunk rule uses statistical baselining, this Sigma rule identifies prompts above an absolute size, which may indicate prompt injection, data exfiltration, or service abuse.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - exfiltration
    techniques:
      - T1560.002
      - T1567.002
    data_sources:
      - cloud
      - aws
      - bedrock
rules_count: 1
---

This brief details the detection of unusually large prompts directed at Amazon Web Services (AWS) Bedrock Claude models. While the original Splunk detection identifies these anomalies by calculating the statistical baseline of input token counts (flagging requests exceeding a certain standard deviation above the mean), the underlying behavior of submitting excessively large prompts is a key indicator of potential malicious activity. Such activities include prompt injection attacks, where attackers manipulate the model's behavior, attempts at data exfiltration through clever prompt design, or general abuse of the AI service, leading to increased costs and resource consumption. This detection is crucial for organizations utilizing AI models to identify and mitigate risks associated with their misuse. It requires careful configuration of AWS Bedrock model invocation logging and subsequent analysis of token counts within those logs.

## Impact

Successful prompt injection attacks can lead to unauthorized information disclosure, manipulation of AI model outputs, or bypassing of security controls, potentially causing reputational damage, data breaches, or financial losses. Data exfiltration attempts via large prompts could allow attackers to bypass traditional network defenses and extract sensitive information from internal systems by having the AI model embed it in its responses. Moreover, the abuse of AI services through excessively large or complex prompts can result in significant, unexpected infrastructure costs for the organization and degrade the service quality for legitimate users. The observed impact typically involves compromise of data integrity, confidentiality, and service availability, along with financial strain from misused cloud resources.

## Recommendation

*   Deploy the Sigma rule in this brief to your SIEM and tune the `input.inputTokenCount` threshold to fit your environment's typical usage patterns.
*   Enable Amazon Bedrock model invocation logging (as outlined in `https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html`) to ensure `input.inputTokenCount` and other relevant invocation details are captured for detection and analysis.
*   Review potential false positives as described in this brief, such as legitimate complex queries or multi-turn conversations that naturally involve large prompt sizes, and create appropriate baselines or allowlists.
*   Monitor `identity.arn` and `accountId` fields for any entities consistently generating large prompts, investigating their legitimacy and purpose.
