---
title: Detection of Credential Exposure in Azure AI Foundry Interactions
slug: 2026-10-azure-ai-credential-leakage
description: This detection monitors Azure API Management GatewayLogs for sensitive credential patterns accidentally included in LLM prompts or assistant replies, flagging potential data leakage through AI services.
date: "2026-10-05T17:57:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure-ai-foundry
  - credential-access
  - genai
  - data-leakage
  - cloud-security
vendors:
  - Microsoft
products:
  - Azure AI Foundry
  - Azure API Management
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Detects a Microsoft Foundry chat, sent through API Management, whose prompt or assistant reply contains a known credential pattern.
    confidence_band: high
references:
  - https://www.elastic.co/docs/reference/integrations/azure_ai_foundry
  - https://learn.microsoft.com/en-us/azure/api-management/diagnostic-logs-reference
  - https://genai.owasp.org/llmrisk/llm06-sensitive-information-disclosure
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy credential detection logic to monitor GatewayLogs via the Azure AI Foundry integration.
      owner: Detection Engineering
      due: 72h
      evidence: Integration setup requirements.
  mitigation_plan:
    - priority: immediate
      action: Rotate any credentials found in logs if they match live secret patterns.
      owner: SOC
      addresses: Leaked credentials
      evidence: Investigation guide.
---

Organizations utilizing Azure AI Foundry through API Management are at risk of sensitive information disclosure when users or automated processes inadvertently include secrets, such as API keys, private keys, or credentials, within LLM prompts. Because Azure content filters often do not flag these prompts as policy violations, the secrets are processed and potentially echoed back in assistant completions. This exposure occurs at the application layer and is recorded within API Management GatewayLogs. Defenders must ingest these logs with backend request and response bodies to achieve visibility. Detecting these patterns is essential to preventing LLM data leakage, identifying compromised credentials for rotation, and tracing the source of the exposure to specific API Management subscriptions.

## Impact

Successful exploitation or accidental disclosure results in the exposure of live authentication secrets, potentially leading to unauthorized access to downstream cloud services, developer environments, or internal APIs. Organizations may suffer from secondary credential abuse, such as unauthorized cloud infrastructure access using leaked AWS keys, private keys, or OAuth tokens transmitted through AI interfaces.

## Recommendation

- Enable Azure API Management GatewayLogs with backend request and response body logging to capture full interaction text.
- Implement the provided detection logic to monitor API Management logs for patterns matching known credential structures (e.g., AWS access keys, GitHub tokens, Slack tokens, private keys).
- Treat all detections as potential incidents; rotate or revoke any identified live credentials immediately.
- Restrict access to raw API request/response logs to authorized security teams, as these logs retain the cleartext secrets that triggered the alert.
