---
title: AWS Bedrock Claude Abuse and Data Exposure Detection Coverage
slug: 2026-07-aws-bedrock-claude-large-prompts
description: Merged detection coverage for AWS Bedrock Claude abuse patterns, including
  prompt injection, sensitive-data exposure, high-risk tool invocation, cross-region
  inference, hostile prompts, unusually large prompts, and excessive token output
  anomalies.
date: '2026-07-07T08:09:32Z'
lastmod: '2026-07-07T10:07:42Z'
type: coverage
types:
- coverage
severities:
- high
tags:
- cloud
- aws
- bedrock
- claude
- llm
- prompt-injection
- data-exfiltration
- detection-coverage
vendors:
- AWS
- Anthropic
- Splunk
products:
- AWS Bedrock Claude
references:
- https://github.com/splunk/security_content/blob/main/detections/application/aws_bedrock_claude_cross_region_possible_inference_abuse.yml
- https://aws.amazon.com/blogs/apn/unlocking-the-power-of-splunk-with-amazon-bedrock-an-agentic-ai-approach-to-build-customized-splunk-assistants-using-bedrock-agents/
- https://help.splunk.com/en/splunk-observability-cloud/observability-for-ai/splunk-ai-infrastructure-monitoring/set-up-ai-infrastructure-monitoring/amazon-bedrock
- https://research.splunk.com/stories/aws_bedrock_security/
- https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
- https://github.com/splunk/security_content/blob/main/detections/application/aws_bedrock_claude_hostile_prompt_sentiment.yml
- https://github.com/splunk/security_content/blob/main/detections/application/aws_bedrock_claude_high_risk_filesystem_and_exec_tool_invocation.yml
rules:
- title: AWS Bedrock Claude Possible Cross-Region Inference Abuse (High Tokens)
  description: Detects potential cross-region inference abuse in AWS Bedrock Claude
    models by identifying invocations with high input token counts (>=2000) where
    the 'region' and 'inferenceRegion' fields are present. This rule flags high-volume
    Bedrock activity; a critical next step for detection engineers is to correlate
    these events and filter for instances where 'region' is NOT equal to 'inferenceRegion'
    in their SIEM, as direct field comparison is not standard Sigma.
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
- title: Detect Hostile Prompts in AWS Bedrock Claude
  description: Detects prompts with hostile or aggressive sentiment sent to AWS Bedrock
    Claude models, indicative of potential abuse, harassment, or malicious intent
    against the LLM.
  platform: sigma
  severity: medium
  data_sources:
  - api_call
  - aws.bedrock
- title: Detect Large Prompts in AWS Bedrock Claude
  description: Detects AWS Bedrock Claude invocation requests with an input token
    count exceeding a specified large threshold. While the source Splunk rule uses
    statistical baselining, this Sigma rule identifies prompts above an absolute size,
    which may indicate prompt injection, data exfiltration, or service abuse.
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
- title: Detect AWS Bedrock Claude Possible Prompt Injection Keywords
  description: Detects phrases in AWS Bedrock Claude prompts commonly associated with
    prompt injection or jailbreak attempts, such as instruction overrides or requests
    to ignore prior guidance. This is a hunting rule due to high false positives,
    requiring further investigation of context.
  platform: sigma
  severity: low
  tactics:
  - defense_evasion
  techniques:
  - T1055
  data_sources:
  - cloud
  - aws
- title: Detect Sensitive Data in AWS Bedrock Claude Prompts
  description: Detects sensitive data such as AWS keys, GitHub tokens, Slack tokens,
    Stripe keys, OpenAI keys, Google API keys, private keys, generic passwords, bearer
    tokens, Social Security Numbers (SSNs), and credit card numbers being sent in
    prompts to AWS Bedrock Claude models. This indicates potential data leakage or
    insider threat.
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
- title: Detect AWS Bedrock Claude High-Risk Tool Invocation
  description: Detects identities causing AWS Bedrock Claude to invoke high-risk filesystem
    or execution tools such as bash, curl, edit, write, webfetch, grep, read, or read_file.
    This indicates anomalous behavior that could lead to privilege escalation, data
    exfiltration, or unauthorized command execution.
  platform: sigma
  severity: high
  tactics:
  - collection
  - command_and_control
  - discovery
  - execution
  - exfiltration
  techniques:
  - T1005
  - T1041
  - T1059.004
  - T1083
  - T1105
  data_sources:
  - cloud
  - aws
rules_count: 6
updates:
- at: '2026-07-07T08:09:32Z'
  level: L2
  summary: 'added detection rule: AWS Bedrock Claude Possible Cross-Region Inference
    Abuse (High Tokens)'
  sources:
  - splunk-escu
  source_urls:
  - https://github.com/splunk/security_content/blob/main/detections/application/aws_bedrock_claude_cross_region_possible_inference_abuse.yml
- at: '2026-07-07T08:10:55Z'
  level: L1
  summary: 'added anomaly coverage: Detecting Excessive AWS Bedrock Claude Token Usage'
  sources:
  - splunk-escu
  source_urls:
  - https://aws.amazon.com/blogs/apn/unlocking-the-power-of-splunk-with-amazon-bedrock-an-agentic-ai-approach-to-build-customized-splunk-assistants-using-bedrock-agents/
- at: '2026-07-07T08:22:03Z'
  level: L1
  summary: 'added detection rule: Detect Hostile Prompts in AWS Bedrock Claude'
  sources:
  - splunk-escu
  source_urls:
  - https://github.com/splunk/security_content/blob/main/detections/application/aws_bedrock_claude_hostile_prompt_sentiment.yml
- at: '2026-07-07T08:18:14Z'
  level: L1
  summary: 'added detection rule: Detect Large Prompts in AWS Bedrock Claude'
  sources:
  - splunk-escu
  source_urls:
  - https://aws.amazon.com/blogs/apn/unlocking-the-power-of-splunk-with-amazon-bedrock-an-agentic-ai-approach-to-build-customized-splunk-assistants-using-bedrock-agents/
- at: '2026-07-07T08:15:08Z'
  level: L1
  summary: 'added detection rule: Detect AWS Bedrock Claude Possible Prompt Injection
    Keywords'
  sources:
  - splunk-escu
  source_urls:
  - https://aws.amazon.com/blogs/apn/unlocking-the-power-of-splunk-with-amazon-bedrock-an-agentic-ai-approach-to-build-customized-splunk-assistants-using-bedrock-agents/
- at: '2026-07-07T08:16:49Z'
  level: L2
  summary: 'added detection rule: Detect Sensitive Data in AWS Bedrock Claude Prompts'
  sources:
  - splunk-escu
  source_urls:
  - https://aws.amazon.com/blogs/apn/unlocking-the-power-of-splunk-with-amazon-bedrock-an-agentic-ai-approach-to-build-customized-splunk-assistants-using-bedrock-agents/
- at: '2026-07-07T08:12:29Z'
  level: L2
  summary: 'added detection rule: Detect AWS Bedrock Claude High-Risk Tool Invocation'
  sources:
  - splunk-escu
  source_urls:
  - https://github.com/splunk/security_content/blob/main/detections/application/aws_bedrock_claude_high_risk_filesystem_and_exec_tool_invocation.yml
---
This consolidated coverage brief tracks AWS Bedrock Claude abuse detections that were previously published as separate rule-specific briefs. The coverage focuses on suspicious model invocation patterns visible in Bedrock invocation logs and downstream SIEM telemetry: prompt injection keywords, hostile prompt sentiment, sensitive data in prompts, unusually large prompts, excessive output-token anomalies, cross-region inference mismatches, and high-risk filesystem or execution tool invocation through Claude workflows.

## Detection Coverage

Defenders should enable Amazon Bedrock model invocation logging, route request and response metadata into their SIEM, and deploy the rules in this brief as a single monitoring package for Claude usage. Treat high-risk tool invocation and sensitive-data prompt exposure as higher-priority findings, especially when tied to human identities, unusual regions, or identities deviating from historical token baselines.

## Recommendation

* Enable AWS Bedrock model invocation logging and ingest Claude request/response metadata into Splunk or an equivalent SIEM.
* Deploy the six public detection rules in this brief and tune thresholds for expected developer, red-team, and testing activity.
* Investigate identities triggering multiple Bedrock Claude detections on the same day, especially combinations of prompt injection, sensitive data exposure, cross-region inference, and high-risk tool usage.
