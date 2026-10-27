---
brief_id: brief-2026-10-27-azure-ai-keys-access
event_id: brief-2026-10-27-azure-ai-keys-access
revision: 1
activity_at: "2026-10-27T23:35:10Z"
title: 'Microsoft Azure AI Foundry: Unauthorized API key and connection secret access'
slug: 2026-10-azure-ai-keys-access
description: High-privilege Azure principals accessing Microsoft Foundry API keys or connection secrets are being monitored to prevent LLMjacking and unauthorized data pivoting.
date: "2026-10-27T23:35:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic requires environment-specific tuning for service principals.
tags:
  - credential-access
  - cloud-security
  - azure
  - llmjacking
vendors:
  - Microsoft
products:
  - Azure AI Services
  - Azure AI Foundry
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    subtechnique_id: T1555.006
    subtechnique_name: Cloud Secrets Management Stores
    evidence: A compromised identity retrieving these keys is a common first step in LLMjacking and in pivoting from a Foundry project to the data it is connected to.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    subtechnique_id: T1078.004
    subtechnique_name: Cloud Accounts
    evidence: Identifies the first time in seven days that a high-privilege Azure principal lists or regenerates the API keys.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/azure/ai-services/authentication
  - https://learn.microsoft.com/en-us/azure/ai-foundry/how-to/connections-add
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/credential_access_azure_ai_foundry_keys_or_connection_secrets_accessed.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify infrequent or first-time key listing or secret reading by privileged accounts
      technique_id: T1555.006
      data_needed:
        - Azure Activity Logs (Microsoft.CognitiveServices/accounts/listKeys/action, etc.)
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: This rule fires when a high-privilege principal that has not done so for that resource in the last seven days lists or regenerates account keys, or reads account or project connection secrets.
  mitigation_plan:
    - priority: immediate
      action: Set disableLocalAuth on Azure AI Foundry accounts to enforce Entra ID authentication
      owner: IT Operations
      addresses: Credential theft
      evidence: Set disableLocalAuth on the account to require Entra ID authentication instead of keys where possible.
---

Microsoft Foundry (Azure AI Services) accounts store API keys that grant inference access across all model deployments, bypassing Entra ID conditional access. These accounts and projects also store connection secrets for downstream services such as Azure OpenAI, storage, and search. Threat actors use compromised high-privilege identities to retrieve these keys or secrets as a primary step for LLMjacking and lateral movement into connected data resources.

## Impact

Successful retrieval of API keys enables unauthorized inference usage, leading to potential financial loss and data exposure. Disclosure of connection secrets allows attackers to pivot from an AI project to integrated Azure services.

## Recommendation

- Monitor Azure Activity Logs for administrative operations involving key listing, regeneration, or secret retrieval by high-privilege principals.
- Prioritize the use of Entra ID authentication for AI services and set 'disableLocalAuth' on Foundry accounts where key-based access is not strictly required.
- Review and audit high-privilege roles (e.g., Owner, Contributor) assigned to AI resource groups.
- Exclude automated service principals from monitoring via an allowlist if they require routine access to secrets for deployment pipelines.
