---
brief_id: brief-2026-10-20-llmjacking-gcp
event_id: brief-2026-10-20-llmjacking-gcp
revision: 3
activity_at: "2026-11-03T22:02:23Z"
revision_history:
  - revision: 2
    at: "2026-10-27T23:36:18Z"
    checksum: sha256:b41a8f7dd7ef622927b2da3d9da5d6bcc1e9072c0c6068c0be8601d87291f7ac
    summary: added coverage for Vertex AI
    changed_fields:
      - action_plan
      - affected_products
      - iocs
      - lastmod
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp_vertexai/initial_access_gcp_vertexai_inference_by_caller_from_new_asn.toml
  - revision: 3
    at: "2026-11-03T22:02:23Z"
    checksum: sha256:61be6b825df7200cea18d7d425b8f6e8b00ce0797fd41c5c3ce4e505ff3b8821
    summary: added coverage for Vertex AI
    changed_fields:
      - action_plan
      - claim_state
      - iocs
      - lastmod
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp_vertexai/impact_gcp_vertexai_high_request_and_token_volume.toml
title: 'Google Cloud Platform: Billing account hijacking for unauthorized AI usage'
slug: 2026-10-llmjacking-gcp
description: Threat actors are hijacking Google Cloud Platform billing accounts via phishing and policy manipulation to conduct large-scale, unauthorized LLM inference, resulting in significant financial losses for victims.
date: "2026-10-20T23:53:02Z"
lastmod: "2026-11-03T22:00:22Z"
type: advisory
claim_state: <nil>
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
cpes:
  - cpe:2.3:a:google:google_cloud_platform:*:*:*:*:*:*:*:*
tags:
  - cloud-security
  - phishing
  - billing-fraud
  - identity-compromise
  - cloud
  - gcp
  - llmjacking
  - vertex-ai
  - genai
  - credential-access
  - data-leakage
  - prompt-injection
  - defense-evasion
  - impact
vendors:
  - Google
products:
  - Google Cloud Platform
  - Vertex AI
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.002
    subtechnique_name: Spearphishing Link
    evidence: The attack began with a classic yet efficient phishing tactic. The threat actor purchased Google Search ads for common administrative search terms.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    subtechnique_id: T1136.003
    subtechnique_name: Cloud Account
    evidence: With domain restrictions lifted, the compromised user account was leveraged to add external actor-controlled Gmail accounts directly into the organization's billing account.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    subtechnique_id: T1098.001
    subtechnique_name: Additional Cloud Credentials
    evidence: The role roles/billing.admin granted full control over the billing account, including the ability to manage permissions, attach external projects, and alter payment settings.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    subtechnique_id: T1078.004
    subtechnique_name: Cloud Accounts
    evidence: In each of the intrusions investigated, Wiz CIRT observed that after the initial login, subsequent threat actor activity shifted to originate from IP addresses geolocated within each victim organization's headquartered country.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    subtechnique_id: T1078.004
    subtechnique_name: Cloud Accounts
    evidence: Stolen Google Cloud credentials, including exported service account keys and OAuth tokens, are used for LLMjacking from attacker infrastructure.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Detects a GCP Vertex AI GenerateContent exchange whose prompt or model reply contains a known credential pattern.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Detects Vertex AI GenerateContent prompts that match common jailbreak / instruction-override heuristics.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
    evidence: High request and token volume can indicate model extraction, quota abuse, or a compromised caller.
    confidence_band: high
references:
  - https://www.wiz.io/blog/from-phishing-to-llmjacking
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/persistence_gcp_vertexai_role_granted.toml
  - https://cloud.google.com/vertex-ai/docs/general/audit-logging
  - https://www.elastic.co/docs/reference/integrations/gcp_vertexai
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp_vertexai/initial_access_gcp_vertexai_inference_by_caller_from_new_asn.toml
  - https://genai.owasp.org/llmrisk/llm06-sensitive-information-disclosure
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp_vertexai/credential_access_gcp_vertexai_credentials_in_prompt.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp_vertexai/defense_evasion_gcp_vertexai_jailbreak_prompt_heuristics.toml
  - https://cloud.google.com/blog/products/identity-security/introducing-ai-protection-security-for-the-ai-era
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp_vertexai/defense_evasion_gcp_vertexai_repeated_assistant_refusals.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp_vertexai/defense_evasion_gcp_vertexai_safety_filters_disabled.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp_vertexai/impact_gcp_vertexai_high_request_and_token_volume.toml
iocs:
  - type: ip
    value: 212.73.134.136
  - type: domain
    value: '*.gboogl.com'
  - type: domain
    value: '*.groosl.com'
  - type: domain
    value: '*.gprokl.com'
  - type: domain
    value: '*.gxoosl.com'
  - type: domain
    value: '*.gsoolg.com'
  - type: domain
    value: gzoozl.com
  - type: domain
    value: groonl.com
  - type: domain
    value: gsool.space
  - type: domain
    value: gbrokl.space
  - type: domain
    value: gbrokl.xyz
  - type: domain
    value: gsoosl.xyz
  - type: domain
    value: gsool.xyz
  - type: domain
    value: gpoosl.com
  - type: domain
    value: groolg.com
  - type: domain
    value: gcslom.com
  - type: domain
    value: gcoalg.com
ioc_counts:
  domain: 16
  ip: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - CTI
    - Detection Engineering
  immediate_actions:
    - action: Hunt for logins from IP 212.73.134.136 in GCP and Google Workspace audit logs.
      owner: SOC
      due: 24h
      evidence: Source lists this as infrastructure seen in initial phishing logins.
    - action: Deploy logic to scan GCP Vertex AI prompt/response logs for credential patterns (e.g., AWS keys, GitHub tokens, private keys).
      owner: Detection Engineering
      due: 48h
      evidence: Source provides patterns for AWS access keys, GitHub tokens, PEM private keys, and others.
  hunt_leads:
    - lead: Identify modification of organization policy "iam.allowedPolicyMemberDomains".
      technique_id: T1098
      data_needed:
        - GCP Admin Activity Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The threat actor deleted safety policies at the organization level, such as iam.allowedPolicyMemberDomains.
    - lead: Identify anomalies in GCP Vertex AI model inference traffic originating from hosting providers or unrecognized geographic regions.
      technique_id: T1078.004
      data_needed:
        - GCP Data Access Audit Logs (aiplatform.googleapis.com)
        - source.as.organization.name
        - client.user.email
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Stolen Google Cloud credentials... used for LLMjacking from attacker infrastructure.
    - lead: Search for high-entropy strings or known secret prefixes in Vertex AI prompt-response logs.
      technique_id: T1552
      data_needed:
        - logs-gcp_vertexai.prompt_response_logs-*
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Secrets in prompt/response logs are visible to anyone with access to BigQuery prompt-response export.
    - lead: Identify potential prompt injection attempts by searching for common jailbreak strings in Vertex AI request logs
      technique_id: T1562
      data_needed:
        - gcp.vertexai.prompt_response_logs.full_request.contents.parts.text
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The heuristic identifies common prompt-injection language and instruction-override attempts within GCP Vertex AI prompt response logs.
    - lead: Identify anomalous concentration of source IP and client user emails for high-volume models
      technique_id: T1496
      data_needed:
        - logs-gcp_vertexai.auditlogs-* (GenerateContent operations)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Pivot to logs-gcp_vertexai.auditlogs-* GenerateContent for source.ip and client.user.email concentration in the same window.
  mitigation_plan:
    - priority: immediate
      action: Implement strict identity governance and multi-factor authentication (MFA) enforcement across all GCP administrator accounts.
      owner: IT Operations
      addresses: Initial Access
      evidence: Attacker used phishing to bypass standard authentication.
    - priority: immediate
      action: Revoke compromised service account keys, OAuth tokens, and reset user sessions for accounts observed accessing Vertex AI from suspicious ASNs.
      owner: IT Operations
      addresses: T1078.004
      evidence: If the activity is not authorized, disable or delete the service account key, revoke the user sessions and OAuth tokens.
    - priority: immediate
      action: Implement Model Armor or sensitive-data filtering policies on Vertex AI API requests.
      owner: IT Operations
      addresses: Credential exposure in logging
      evidence: Find and fix the application path that placed the secret in the prompt; add input/output filtering (Model Armor / sensitive-data policies).
    - priority: medium
      action: Enable Model Armor / AI Protection for native jailbreak and prompt injection signaling
      owner: Cloud Security
      addresses: Prompt injection and jailbreak risk
      evidence: Model Armor findings remain the preferred first-party jailbreak signal when that API is enabled.
    - priority: short_term
      action: Implement quota limits for Vertex AI API usage per model and project
      owner: IT Operations
      addresses: Unauthorized AI Usage
      evidence: Restrict or rotate caller credentials, apply quotas, and review spend/billing for the model.
updates:
  - at: "2026-10-27T23:35:36Z"
    level: L1
    summary: added coverage for Vertex AI
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp_vertexai/initial_access_gcp_vertexai_inference_by_caller_from_new_asn.toml
  - at: "2026-11-03T22:00:12Z"
    level: L1
    summary: added coverage for Vertex AI
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp_vertexai/credential_access_gcp_vertexai_credentials_in_prompt.toml
  - at: "2026-11-03T22:00:16Z"
    level: L1
    summary: added coverage for Vertex AI
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp_vertexai/defense_evasion_gcp_vertexai_jailbreak_prompt_heuristics.toml
  - at: "2026-11-03T22:00:22Z"
    level: L1
    summary: added coverage for Vertex AI
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp_vertexai/impact_gcp_vertexai_high_request_and_token_volume.toml
---

The Wiz Customer Incident Response Team (CIRT) has identified a trend where threat actors compromise Google Cloud Platform (GCP) credentials to hijack billing accounts for unauthorized AI resource consumption. By leveraging phishing campaigns via sponsored search ads, attackers obtain valid user credentials and MFA codes. Once access is gained, they perform privilege escalation and modify organizational policies, such as 'iam.allowedPolicyMemberDomains', to remove guardrails that restrict IAM membership to verified domains. This allows the integration of external, attacker-controlled accounts. The attackers then link external GCP projects to the victim's billing account. By executing AI workloads within these foreign projects, the actors obfuscate their prompts and outputs from the victim's visibility while simultaneously billing the victim for all API usage. This 'LLMjacking' activity leads to rapid billing surges, often reaching hundreds of thousands of dollars within 48 hours of initial compromise.

## Attack Chain

1. Attacker purchases sponsored search ads for terms like "google cloud" to host phishing kits on Google Sites.
2. Victim clicks the malicious ad, provides credentials and MFA tokens on a deceptive login page, which captures the data and redirects to a legitimate Google prompt.
3. Attacker uses harvested credentials to initiate login, bypassing MFA through the captured session data.
4. Attacker enables the Gemini API in existing, low-usage projects and creates service accounts with high-privileged roles (e.g., 'roles/ml.admin').
5. Attacker dismantles organizational policies by deleting 'iam.allowedPolicyMemberDomains' to allow external account access.
6. Attacker invites external attacker-controlled accounts to the organization's billing account and assigns the 'roles/billing.admin' role.
7. Attacker links their external GCP projects to the victim's billing account to offload AI API costs.
8. Attacker demotes original billing administrators to 'viewer' roles to prevent detection and reclamation of administrative control.

## Impact

Victim organizations in the cloud sector have faced significant financial damage, with unauthorized Gemini API charges reaching tens to hundreds of thousands of dollars within 48 hours. Because workloads are executed in foreign projects, organizations lack visibility into the nature of the data being processed, creating both financial and data security risks.

## Recommendation

* Monitor Google Workspace and GCP audit logs for logins originating from the documented IP infrastructure (212.73.134.136).
* Regularly audit GCP IAM configurations for unexpected additions of external domains or personal email addresses (e.g., @gmail.com) to high-privileged roles.
* Audit GCP organization policies for modifications to 'iam.allowedPolicyMemberDomains', as this is a primary indicator of disabling organizational guardrails.
* Monitor for unexpected enabling of the Gemini API product in projects, especially those with minimal historical activity.
* Proactively audit billing account permissions to ensure only authorized corporate identities hold 'roles/billing.admin' or other administrative roles.
