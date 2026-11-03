---
brief_id: brief-2026-10-27-azure-ai-foundry-filter-tamper
event_id: brief-2026-10-27-azure-ai-foundry-filter-tamper
revision: 2
activity_at: "2026-11-03T21:43:45Z"
revision_history:
  - revision: 2
    at: "2026-11-03T21:43:45Z"
    checksum: sha256:9263b5f6c634bff7a1ded2f2c89c72697e08fc474837104731aa914fa1b0fcb3
    summary: added coverage for Azure AI Foundry
    changed_fields:
      - action_plan
      - affected_products
      - lastmod
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure_ai_foundry/impact_azure_ai_foundry_high_request_and_token_volume.toml
title: 'Microsoft Azure AI Foundry: Responsible AI policy tampering'
slug: 2026-10-azure-ai-foundry-filter-tamper
description: Adversaries with administrative access can weaken or delete Azure AI Foundry content filters and blocklists to bypass model guardrails and monitoring controls, effectively impairing defensive security instrumentation.
date: "2026-10-27T23:35:22Z"
lastmod: "2026-11-03T21:43:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
qa_status:
  verdict: pass
tags:
  - azure
  - defense-evasion
  - cloud-security
  - genai
  - cloud
  - impact
vendors:
  - Microsoft
products:
  - Azure AI Foundry
  - Azure API Management
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    subtechnique_id: T1562.001
    subtechnique_name: Disable or Modify Tools
    evidence: An adversary with control of the account can weaken or remove these filters so that harmful prompts and outputs are no longer blocked or logged as filtered.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Detects a Microsoft Foundry chat, sent through API Management, where Azure sets jailbreak.detected on the prompt.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
    evidence: Detects one caller IP sending a high number of requests and consuming a high number of tokens against the same Foundry deployment and operation during the rule lookback.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/azure/ai-foundry/openai/concepts/content-filter
  - https://learn.microsoft.com/en-us/azure/ai-foundry/openai/how-to/content-filters
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/defense_evasion_azure_ai_foundry_content_filter_modified_or_deleted.toml
  - https://www.elastic.co/docs/reference/integrations/azure_ai_foundry
  - https://learn.microsoft.com/en-us/azure/ai-services/openai/concepts/content-filter
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure_ai_foundry/defense_evasion_azure_ai_foundry_jailbreak_detected.toml
  - https://learn.microsoft.com/en-us/azure/ai-foundry/openai/how-to/monitor-openai
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure_ai_foundry/impact_azure_ai_foundry_high_request_and_token_volume.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security Team
    - Detection Engineering
  immediate_actions:
    - action: 'Deploy alerting for operations: MICROSOFT.COGNITIVESERVICES/ACCOUNTS/RAIPOLICIES/WRITE, DELETE and RAIBLOCKLISTS/WRITE, DELETE'
      owner: Detection Engineering
      due: 48h
      evidence: Source identifies these specific operations as indicators of policy modification.
    - action: Enable logging of backend response bodies in Azure API Management diagnostics.
      owner: IT Operations
      due: 48h
      evidence: Setup section requires GatewayLogs with backend response body to access jailbreak.detected flag.
  hunt_leads:
    - lead: Identify unauthorized RAI policy changes and correlate with account activity
      technique_id: T1562.001
      data_needed:
        - Azure Activity Logs (operation_name, principal_id, source.ip)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Adversaries with control of the account can weaken or remove these filters.
    - lead: Identify repeated jailbreak detections from specific source IPs or subscription IDs.
      technique_id: AML.T0054
      data_needed:
        - Azure API Management GatewayLogs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Look for other GatewayLogs from the same IP or subscription in the same window, including repeated refusals.
    - lead: Identify anomalies in Azure AI Foundry RequestResponse logs by aggregating request counts and token consumption by caller IP prefix.
      technique_id: T1496
      data_needed:
        - Azure AI Foundry RequestResponse diagnostic logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: One masked caller IP exceeded the request count and combined token sum in the query, on one deployment and operation during the rule lookback.
  mitigation_plan:
    - priority: immediate
      action: Restrict RBAC permissions for Microsoft.CognitiveServices/accounts/raiPolicies/* to a minimum set of administrators
      owner: Identity and Access Management
      addresses: Unauthorized modification of RAI policies
      evidence: Restrict Microsoft.CognitiveServices/accounts/raiPolicies/* permissions to a small set of administrators.
    - priority: immediate
      action: Rotate compromised API Management subscription keys and block associated source IPs.
      owner: SOC
      addresses: Unauthorized LLM usage
      evidence: Response and remediation section
    - priority: immediate
      action: Apply rate limits or quotas on Azure AI Foundry deployments showing anomalous token consumption.
      owner: IT Operations
      addresses: T1496
      evidence: Apply a lower rate limit or quota on the deployment until the caller is identified.
updates:
  - at: "2026-11-03T21:42:58Z"
    level: L1
    summary: added coverage for Azure AI Foundry +1 products
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure_ai_foundry/defense_evasion_azure_ai_foundry_jailbreak_detected.toml
  - at: "2026-11-03T21:43:11Z"
    level: L1
    summary: added coverage for Azure AI Foundry
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure_ai_foundry/impact_azure_ai_foundry_high_request_and_token_volume.toml
---

Microsoft Azure AI Services (Foundry) utilizes Responsible AI (RAI) policies to regulate prompt and completion categories, identify jailbreak attempts, and block protected material. These guardrails are configured via RAI policies (`Microsoft.CognitiveServices/accounts/raiPolicies`) and term-level blocklists (`raiBlocklists`). An adversary with sufficient administrative privileges can modify or delete these configurations to neutralize safety guardrails. Such actions prevent the platform from blocking or logging harmful model interactions, thereby removing critical visibility into adversarial usage of AI deployments.

## Impact

Successful manipulation of RAI policies disables security controls over AI model inputs and outputs. This allows for the execution of harmful prompts, injection of malicious payloads, and data exfiltration through AI models without triggering platform-native alerts or blocks.

## Recommendation

- Monitor Azure Activity Logs for administrative write or delete operations against RAI policies and custom blocklists.
- Establish a principle of least privilege by restricting `Microsoft.CognitiveServices/accounts/raiPolicies/*` permissions to a highly limited group of authorized administrators.
- Integrate Azure Activity Logs into your SIEM/XDR platform to alert on modifications to the Cognitive Services control plane.
- Audit existing RAI policy configurations and verify that any observed modifications align with approved change management records.
