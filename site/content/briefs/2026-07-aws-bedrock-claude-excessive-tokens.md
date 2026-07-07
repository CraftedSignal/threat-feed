---
title: Detecting Excessive AWS Bedrock Claude Token Usage
slug: 2026-07-aws-bedrock-claude-excessive-tokens
description: This detection identifies anomalous behavior in AWS Bedrock Claude where an identity generates excessively large model responses compared to its historical average, signaling potential bulk data exfiltration, successful prompt injection leading to verbose output, or a runaway agentic loop indicative of abuse or compromise of the large language model.
date: "2026-07-07T08:10:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloud
  - ai-ml
  - anomaly-detection
  - cost-abuse
  - data-exfiltration
vendors:
  - Amazon
products:
  - Amazon Bedrock
  - Claude
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
    evidence: bulk data extraction
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Resource Hijacking
    technique_id: T1496
    technique_name: Resource Hijacking
    evidence: a runaway agentic loop hitting context limits
    confidence_band: high
references:
  - https://aws.amazon.com/blogs/apn/unlocking-the-power-of-splunk-with-amazon-bedrock-an-agentic-ai-approach-to-build-customized-splunk-assistants-using-bedrock-agents/
  - https://help.splunk.com/en/splunk-observability-cloud/observability-for-ai/splunk-ai-infrastructure-monitoring/set-up-ai-infrastructure-monitoring/amazon-bedrock
  - https://research.splunk.com/stories/aws_bedrock_security/
  - https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
---

This brief details a detection focused on identifying anomalous usage patterns within AWS Bedrock Claude models. Specifically, it targets identities generating unusually large model responses, quantified by output token counts, relative to their own established historical baselines. This behavior can signify several malicious or abusive activities, including attempts at bulk data extraction, where an attacker coerces the model into outputting sensitive or large volumes of information. It also points to successful prompt injection attacks that manipulate the model into generating verbose, potentially sensitive, or out-of-scope content. Furthermore, it can highlight runaway agentic loops, which deplete resources and incur significant costs by hitting context limits. Such anomalies suggest potential compromise of AWS identities or misuse of the Bedrock service.

## Attack Chain

1.  An attacker obtains unauthorized access to a legitimate AWS identity or service principal with permissions to invoke AWS Bedrock Claude models, likely through compromised credentials or misconfiguration.
2.  The compromised identity is used to submit queries or prompts to the Claude model within Amazon Bedrock.
3.  The attacker crafts malicious prompts designed to elicit verbose output, potentially using prompt injection techniques to bypass guardrails or extract information.
4.  Alternatively, the attacker uses the model for bulk data exfiltration, framing requests to generate extensive summaries, code, or other large-volume content.
5.  The Claude model processes these requests, resulting in responses where the `output_tokens` count is significantly higher than the typical historical maximum for that specific invoking identity.
6.  AWS Bedrock's model invocation logging feature records these interactions, including the anomalously large `output_tokens` in the request/response payloads.
7.  These logs are collected and ingested into a security monitoring platform, which then applies statistical analysis to identify the identity whose single largest response exceeds a predefined threshold (e.g., two standard deviations above its mean).
8.  The sustained or repeated generation of excessive tokens facilitates data exfiltration or leads to significant cloud resource consumption and associated financial costs.

## Impact

Successful exploitation or abuse through excessive token usage in AWS Bedrock Claude can lead to significant financial impact due to inflated cloud costs. More critically, it poses a severe data exfiltration risk, where attackers can leverage the generative capabilities of the LLM to extract sensitive information or intellectual property in large volumes from data the model has access to. Such activity also indicates a potential compromise of AWS identities, which could lead to further lateral movement within the cloud environment. While the number of direct victims from this specific method isn't publicly quantified, any organization utilizing AWS Bedrock with compromised credentials or vulnerable LLM integrations is at risk.

## Recommendation

*   Enable Amazon Bedrock model invocation logging to ensure `output_tokens` data is captured for analysis, as described in the `how_to_implement` section.
*   Configure logging of AWS Bedrock activities to be ingested into your SIEM, following the `how_to_implement` guidance.
*   Implement identity and access management (IAM) best practices for AWS, including least privilege for Bedrock invocation roles, to mitigate initial access risks.
*   Deploy anomaly detection analytics that specifically monitor `output_tokens` for Bedrock Claude usage to identify deviations from established baselines.
