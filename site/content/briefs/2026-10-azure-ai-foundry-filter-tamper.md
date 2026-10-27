---
brief_id: brief-2026-10-27-azure-ai-foundry-filter-tamper
event_id: brief-2026-10-27-azure-ai-foundry-filter-tamper
revision: 1
activity_at: "2026-10-27T23:35:22Z"
title: 'Microsoft Azure AI Foundry: Responsible AI policy tampering'
slug: 2026-10-azure-ai-foundry-filter-tamper
description: Adversaries with administrative access can weaken or delete Azure AI Foundry content filters and blocklists to bypass model guardrails and monitoring controls, effectively impairing defensive security instrumentation.
date: "2026-10-27T23:35:22Z"
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
vendors:
  - Microsoft
products:
  - Azure AI Foundry
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    subtechnique_id: T1562.001
    subtechnique_name: Disable or Modify Tools
    evidence: An adversary with control of the account can weaken or remove these filters so that harmful prompts and outputs are no longer blocked or logged as filtered.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/azure/ai-foundry/openai/concepts/content-filter
  - https://learn.microsoft.com/en-us/azure/ai-foundry/openai/how-to/content-filters
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/defense_evasion_azure_ai_foundry_content_filter_modified_or_deleted.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security Team
  immediate_actions:
    - action: 'Deploy alerting for operations: MICROSOFT.COGNITIVESERVICES/ACCOUNTS/RAIPOLICIES/WRITE, DELETE and RAIBLOCKLISTS/WRITE, DELETE'
      owner: Detection Engineering
      due: 48h
      evidence: Source identifies these specific operations as indicators of policy modification.
  hunt_leads:
    - lead: Identify unauthorized RAI policy changes and correlate with account activity
      technique_id: T1562.001
      data_needed:
        - Azure Activity Logs (operation_name, principal_id, source.ip)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Adversaries with control of the account can weaken or remove these filters.
  mitigation_plan:
    - priority: immediate
      action: Restrict RBAC permissions for Microsoft.CognitiveServices/accounts/raiPolicies/* to a minimum set of administrators
      owner: Identity and Access Management
      addresses: Unauthorized modification of RAI policies
      evidence: Restrict Microsoft.CognitiveServices/accounts/raiPolicies/* permissions to a small set of administrators.
---

Microsoft Azure AI Services (Foundry) utilizes Responsible AI (RAI) policies to regulate prompt and completion categories, identify jailbreak attempts, and block protected material. These guardrails are configured via RAI policies (`Microsoft.CognitiveServices/accounts/raiPolicies`) and term-level blocklists (`raiBlocklists`). An adversary with sufficient administrative privileges can modify or delete these configurations to neutralize safety guardrails. Such actions prevent the platform from blocking or logging harmful model interactions, thereby removing critical visibility into adversarial usage of AI deployments.

## Impact

Successful manipulation of RAI policies disables security controls over AI model inputs and outputs. This allows for the execution of harmful prompts, injection of malicious payloads, and data exfiltration through AI models without triggering platform-native alerts or blocks.

## Recommendation

- Monitor Azure Activity Logs for administrative write or delete operations against RAI policies and custom blocklists.
- Establish a principle of least privilege by restricting `Microsoft.CognitiveServices/accounts/raiPolicies/*` permissions to a highly limited group of authorized administrators.
- Integrate Azure Activity Logs into your SIEM/XDR platform to alert on modifications to the Cognitive Services control plane.
- Audit existing RAI policy configurations and verify that any observed modifications align with approved change management records.
