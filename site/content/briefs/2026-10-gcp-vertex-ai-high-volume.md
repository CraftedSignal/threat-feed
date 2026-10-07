---
title: GCP Vertex AI High Volume Request Pattern Detection
slug: 2026-10-gcp-vertex-ai-high-volume
description: High volumes of GenerateContent requests from a single IP against Vertex AI models indicate potential model extraction, automated scraping, or LLMjacking attacks.
date: "2026-10-07T16:32:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - genai
  - model-theft
  - llmjacking
vendors:
  - Google
products:
  - Google Cloud Vertex AI
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: The detection pattern of high-volume requests fits model extraction and automated scraping consistent with collection techniques.
    confidence_band: high
references:
  - https://www.elastic.co/docs/reference/integrations/gcp_vertexai
  - https://genai.owasp.org/llmrisk/llm10-model-theft
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable GCP Vertex AI audit logging for aiplatform.googleapis.com
      owner: IT Operations
      due: 48h
      evidence: Source setup requirements
  hunt_leads:
    - lead: Identify source IPs with event_count >= 100 for prediction methods
      technique_id: AML.T0024
      data_needed:
        - GCP audit logs (logs-gcp_vertexai.auditlogs-*)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Detection rule logic identifies high-volume threshold at 100 events.
---

Security teams should monitor for anomalous request volumes against Google Cloud Vertex AI models, specifically targeting the `PredictionService.GenerateContent` and `PredictionService.StreamGenerateContent` methods. Observed patterns of high request volume from a single `source.ip` within a short timeframe may signify model theft, systematic automated scraping, or LLMjacking, where an attacker leverages compromised credentials to exhaust prediction quotas or exfiltrate model knowledge. This behavior is documented by the MITRE ATLAS framework as Exfiltration via AI Inference API (AML.T0024) and Denial of AI Service (AML.T0029). Defenders should correlate these high-frequency events with associated service account activity, prompt content, and token volume to differentiate between legitimate batch processing and unauthorized interaction.

## Attack Chain

1. Attacker gains unauthorized access to a Google Cloud principal or service account with permission to query Vertex AI models.
2. Attacker enumerates accessible model resources within the target GCP project.
3. Attacker initiates high-frequency `GenerateContent` or `StreamGenerateContent` calls targeting a specific model resource.
4. Attacker iterates through systematically crafted prompts to probe model responses and extract output patterns.
5. Attacker continues high-volume requests to maximize data exfiltration or deliberately exhausts the organization's prediction quota (LLMjacking).
6. Attacker potentially modifies model configuration via `SetPublisherModelConfig` to obscure future monitoring activity.
7. Attacker achieves final objective of either model weight reconstruction (theft) or resource denial through quota exhaustion.

## Impact

Successful exploitation can lead to intellectual property theft through model extraction, unauthorized costs associated with LLMjacking, or service unavailability for legitimate users of the AI platform. These activities impact data confidentiality, billing integrity, and operational availability for organizations relying on GCP AI services.

## Recommendation

- Enable GCP Vertex AI `auditlogs` for `aiplatform.googleapis.com` to ensure visibility into prediction requests.
- Establish a baseline for normal request volume per model and project to tune thresholds for the detection logic.
- Review billing and quota usage for Vertex AI models for sudden, unexplained spikes.
- If unauthorized activity is identified, rotate credentials for the calling principal and restrict the source IP via VPC Service Controls.
- Pivot to prompt logs to inspect for repetitive probing behavior or large context data dumps indicative of systematic scraping.
