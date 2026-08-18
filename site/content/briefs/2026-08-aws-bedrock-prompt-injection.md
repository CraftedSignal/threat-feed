---
title: Detection of Potential Prompt Injection in AWS Bedrock Claude
slug: 2026-08-aws-bedrock-prompt-injection
description: This detection identifies potential prompt injection or jailbreak attempts against Amazon Bedrock Claude models by monitoring for linguistic patterns designed to override system instructions or bypass safety guardrails.
date: "2026-08-18T20:47:46Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - ai-security
  - prompt-injection
  - aws
vendors:
  - Amazon
products:
  - Bedrock
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This search surfaces AWS Bedrock Claude prompts containing phrases commonly associated with prompt injection or jailbreak attempts.
    confidence_band: med
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/aws_bedrock_claude_possible_prompt_injection.yml
  - https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
action_plan:
  priority: enrich_before_decision
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable Amazon Bedrock model invocation logging.
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into model interactions.
  hunt_leads:
    - lead: Search for high-signal prompt injection phrases in Bedrock invocation logs.
      technique_id: T1059.003
      data_needed:
        - Bedrock model invocation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Patterns identified in splunk-escu research.
---

Security teams should monitor Amazon Bedrock Claude model invocation logs for prompts containing phrases associated with prompt injection, jailbreak attempts, or unauthorized persona switching. Attackers use these techniques to override predefined system instructions, access restricted tools, or exfiltrate data by compelling the model to ignore safety guardrails. Because these linguistic patterns are frequently used in legitimate prompt engineering, role-play, or creative writing, this activity is best categorized as a hunting signal rather than a high-fidelity alert. Defenders must analyze the conversation context, such as the injection source (e.g., untrusted user input vs. expected system prompts) and the presence of iterative attempts after refusal, to differentiate malicious activity from benign usage.

## Impact

Successful prompt injection against LLM-integrated applications can lead to unauthorized data exfiltration, privilege escalation, bypass of safety guardrails, and misuse of connected tools or restricted resources. The potential scope of damage depends on the permissions granted to the AI agent and the sensitivity of the data it can access.

## Recommendation

- Enable Amazon Bedrock model invocation logging to S3 or CloudWatch as described in AWS documentation to capture request and response payloads.
- Ingest Bedrock logs into the SIEM via the AWS Add-on.
- Deploy hunting queries targeting the linguistic patterns identified in this brief (instruction overrides, jailbreak strings, persona switching).
- Tune hunting logic by investigating the message roles and surrounding conversation context to reduce noise from legitimate system prompts.
