---
title: AWS Bedrock Claude Possible Prompt Injection
slug: 2026-07-aws-bedrock-claude-prompt-injection
description: This brief identifies potential prompt injection or jailbreak attempts against AWS Bedrock Claude large language models by searching for specific phrases in user prompts, indicating attempts to subvert model behavior, extract data, or gain unauthorized access to resources.
date: "2026-07-07T08:15:08Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - ai
  - prompt-injection
  - aws
  - hunting
vendors:
  - AWS
  - Anthropic
products:
  - Bedrock
  - Claude
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
    evidence: This search surfaces AWS Bedrock Claude prompts containing phrases commonly associated with prompt injection or jailbreak attempts... such as instruction overrides, persona switching, or requests to ignore prior guidance. These attempts are analogous to injecting unauthorized instructions or data into the LLM's processing flow to alter its behavior and bypass intended safety controls.
    confidence_band: med
references:
  - https://aws.amazon.com/blogs/apn/unlocking-the-power-of-splunk-with-amazon-bedrock-an-agentic-ai-approach-to-build-customized-splunk-assistants-using-bedrock-agents/
  - https://help.splunk.com/en/splunk-observability-cloud/observability-for-ai/splunk-ai-infrastructure-monitoring/set-up-ai-infrastructure-monitoring/amazon-bedrock
  - https://research.splunk.com/stories/aws_bedrock_security/
  - https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
rules:
  - title: Detect AWS Bedrock Claude Possible Prompt Injection Keywords
    description: Detects phrases in AWS Bedrock Claude prompts commonly associated with prompt injection or jailbreak attempts, such as instruction overrides or requests to ignore prior guidance. This is a hunting rule due to high false positives, requiring further investigation of context.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1055
    data_sources:
      - cloud
      - aws
rules_count: 1
---

This hunting brief focuses on detecting potential prompt injection and jailbreak attempts targeting AWS Bedrock Claude large language models (LLMs). The detection logic identifies specific keyword phrases within user prompts that are commonly associated with malicious model manipulation, such as instruction overrides, persona switching, requests to ignore prior guidance, or direct calls for "jailbreak" or "developer mode." While many of these phrases can appear in legitimate use cases (e.g., role-playing, legitimate system prompts), their presence, especially when combined with other indicators or occurring mid-conversation, can signal an attacker's attempt to bypass model guardrails, extract sensitive data, escalate privileges, or access restricted tools via the LLM. This is a hunting activity designed to surface suspicious interactions for deeper investigation, acknowledging a high benign base rate.

## Impact

Successful prompt injection against an LLM like AWS Bedrock Claude can lead to severe consequences, including unauthorized data exfiltration from the model's context or connected systems, privilege escalation within the model's operational environment, or the ability to access and manipulate restricted tools or resources that the LLM is permitted to interact with. Attackers could also bypass safety controls, generate harmful content, or coerce the model into performing actions contrary to its intended purpose, potentially impacting data integrity, confidentiality, and the overall security posture of applications relying on the compromised LLM.

## Recommendation

*   Enable Amazon Bedrock model invocation logging to ensure Claude request/response payloads are delivered to S3 and/or CloudWatch Logs (see the reference to `docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html`), and ingest these logs into your SIEM, specifically ensuring the `Input.InputBodyJson.Messages.Content.Text` field (or equivalent) is parsed.
*   Deploy the provided Sigma rule (or similar logic) to your SIEM system as a hunting query, configured to alert on potential prompt injection phrases within AWS Bedrock Claude logs.
*   Investigate all hits from the detection rule thoroughly, reviewing the surrounding conversation, the message role (system vs. user vs. tool output), and whether the phrase is followed by requests to bypass safety controls, extract sensitive data, or access tools before treating a match as suspicious, as described in the `falsepositives` section of the rule.
*   Regularly review and update the list of prompt injection keywords and patterns in your detection rules as new jailbreak techniques evolve to maintain detection efficacy.
