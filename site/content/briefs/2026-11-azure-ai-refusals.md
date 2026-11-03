---
brief_id: brief-2026-11-03-azure-ai-refusals
event_id: brief-2026-11-03-azure-ai-refusals
revision: 1
activity_at: "2026-11-03T21:43:02Z"
title: 'Microsoft Azure AI Foundry: Repeated assistant refusal detection'
slug: 2026-11-azure-ai-refusals
description: An attacker or automated process attempting to bypass safety guardrails may be identified by monitoring for high-frequency model refusals, specifically three or more assistant rejections within a 15-minute window via Azure API Management.
date: "2026-11-03T21:43:02Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic provided as ES|QL query per source; requires environment setup of Azure log forwarding.
tags:
  - azure
  - genai
  - policy-violation
vendors:
  - Microsoft
products:
  - Azure API Management
  - Azure AI Foundry
references:
  - https://www.elastic.co/docs/reference/integrations/azure_ai_foundry
  - https://learn.microsoft.com/en-us/azure/api-management/diagnostic-logs-reference
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure_ai_foundry/defense_evasion_azure_ai_foundry_repeated_assistant_refusals.toml
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Analyze Azure API Management GatewayLogs for high-frequency completion refusals from singular API keys or source IPs.
      technique_id: AML.T0051
      data_needed:
        - Azure API Management GatewayLogs (backend_response_body.choices.finish_reason, backend_response_body.choices.message.content)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: One client received three or more completed refusals in 15 minutes.
  mitigation_plan:
    - priority: medium
      action: Exclude approved security testing and model evaluation IPs or subscription keys from the detection logic to reduce false positives.
      owner: Detection Engineering
      addresses: Repeated assistant refusals
      evidence: Approved prompt-security tests and model evaluations should be excluded.
---

Azure API Management GatewayLogs can be monitored to detect repeated assistant refusals, which may indicate iterative attempts to bypass LLM safety guardrails through techniques such as prompt injection or jailbreaking. This detection pattern tracks three or more completed refusals by the same client, API Management subscription, and model within a 15-minute timeframe.

## Impact
Repeated refusals indicate active attempts to elicit disallowed content from AI models. While often benign if stemming from automated testing or shared subscription keys behind NAT, these patterns may represent adversarial activity aimed at identifying model vulnerabilities or bypassing safety policies.

## Recommendation
- Configure Azure API Management to emit resource logs (GatewayLogs) and ensure backend response bodies are captured in diagnostics.
- Deploy the provided detection logic to identify clients generating high volumes of refusal responses.
- Investigate alerts by comparing prompt/reply samples against known application behavior; focus on non-standard user agents and unfamiliar geo/ASN sources.
- Block source IPs or rotate subscription keys for entities confirmed to be performing unauthorized prompt injection or jailbreak attempts.
