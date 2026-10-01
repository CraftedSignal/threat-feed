---
title: Abuse of Amazon Bedrock API Keys for Destructive Control-Plane Actions
slug: 2026-10-bedrock-api-key-abuse
description: Threat actors are leveraging stolen Amazon Bedrock API keys, intended for model invocation, to perform unauthorized destructive control-plane actions such as disabling guardrails and logging to facilitate LLMjacking or sabotage.
date: "2026-10-01T20:11:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud-security
  - aws
  - genai
  - bedrock
  - llmjacking
vendors:
  - Amazon
products:
  - Amazon Bedrock
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Using an API key to delete guardrails, custom or imported models, or provisioned throughput, or to disable model invocation logging, is inconsistent with the credential's purpose.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Characteristic of LLMjacking operations (which frequently disable guardrails and logging) or of sabotage following credential theft.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html
  - https://www.beyondtrust.com/blog/entry/aws-bedrock-security-guide-api-keys-detection-response
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Review CloudTrail logs for Bedrock API calls containing callWithBearerToken=true and destructive event names.
      owner: SOC
      due: 24h
      evidence: Rule matches regardless of outcome, because a destructive attempt via a bearer token is suspicious.
  hunt_leads:
    - lead: Identify Bedrock API key usage by generic HTTP clients like python-requests or aiohttp.
      technique_id: T1562
      data_needed:
        - CloudTrail user_agent strings
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Generic HTTP clients (python-requests, aiohttp, curl) are a further LLMjacking indicator.
  mitigation_plan:
    - priority: immediate
      action: Revoke Bedrock API keys if unauthorized access is confirmed.
      owner: IT Operations
      addresses: Unauthorized Bedrock API key usage
      evidence: If unauthorized, revoke the Bedrock API key.
---

Security researchers have identified a pattern of abuse involving Amazon Bedrock API keys, which are bearer tokens designed exclusively for model invocation tasks like `InvokeModel` or `Converse`. Adversaries who steal these keys are using them to perform unauthorized control-plane operations that are inconsistent with the intended use of a bearer token. By leveraging these keys, attackers can systematically destroy or impair security resources, including deleting guardrails, removing custom or imported models, and disabling model invocation logging. This activity is indicative of LLMjacking, where an attacker seeks to bypass AI safety controls, or malicious sabotage following credential theft. Defenders can distinguish these unauthorized calls in AWS CloudTrail logs by checking for the `additionalEventData.callWithBearerToken` field set to true.

## Attack Chain

1. Attacker obtains an Amazon Bedrock API key via credential theft, misconfiguration, or exposure in source code repositories.
2. Attacker initializes a session using the stolen bearer token, typically via generic HTTP clients like python-requests or cURL.
3. Attacker identifies targets within the AWS Bedrock environment by enumerating available guardrails, custom models, or provisioned throughput.
4. Attacker calls destructive management APIs, such as `DeleteGuardrail` or `DeleteCustomModel`, using the bearer token to perform unauthorized deletions.
5. Attacker executes `DeleteModelInvocationLoggingConfiguration` to blind the security team to subsequent malicious AI model interactions.
6. Attacker proceeds to perform LLMjacking operations or further sabotage, utilizing the now-degraded security posture of the affected Bedrock environment.

## Impact

Successful abuse of Bedrock API keys results in the loss of proprietary custom models, the bypass of AI safety guardrails, and the loss of visibility into model usage logs. This enables long-term LLMjacking or silent sabotage of AI-driven applications, potentially leading to unauthorized data exfiltration or malicious manipulation of AI outputs.

## Recommendation

1. Enable AWS CloudTrail logging and ensure `additionalEventData` is captured to detect `callWithBearerToken` activity.
2. Implement the proposed detection logic to identify when bearer tokens are used for management actions instead of invocation tasks.
3. Review all Bedrock-related API key usage for anomalies, such as cross-region access or spikes in usage, to identify potentially compromised phantom users.
4. Revoke compromised Bedrock API keys immediately by attaching an inline deny on `bedrock:CallWithBearerToken` or deactivating the service-specific credential.
5. Audit IAM roles and users for persistence; check for unauthorized IAM access keys created alongside the Bedrock API key compromise.
6. Shift toward short-lived credentials or AWS Security Token Service (STS) for all programmatic access to AWS services, minimizing the risk of bearer token theft.
