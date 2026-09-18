---
title: LLMjacking via Compromised AWS Long-Term IAM Credentials
slug: 2026-09-llmjacking-bedrock
description: Adversaries are abusing stolen long-term AWS IAM access keys to perform unauthorized reconnaissance and high-cost model inference within Amazon Bedrock.
date: "2026-09-18T19:29:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - llm
  - aws
  - llmjacking
  - identity-audit
vendors:
  - Amazon
products:
  - Amazon Bedrock
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
    evidence: Adversaries abuse stolen cloud credentials to discover available AI model capabilities.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Threat actors abuse compromised cloud credentials to run high-volume or high-cost model inference.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_bedrock_model_recon_and_invocation_via_long_term_key.toml
  - https://docs.aws.amazon.com/bedrock/latest/APIReference/API_ListFoundationModels.html
  - https://docs.aws.amazon.com/bedrock/latest/APIReference/API_InvokeModel.html
rules:
  - title: AWS Bedrock Foundation Model Enumeration Followed by Invocation via Long-Term Key
    description: Detects when an AWS principal using long-term IAM user credentials (AKIA*) enumerates available Bedrock foundation models and invokes a model within a 15-minute window, a pattern indicative of LLMjacking.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1078.004
      - T1526
    data_sources:
      - webserver
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule to SIEM to identify potential LLMjacking attempts.
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in brief.
  hunt_leads:
    - lead: Search for historical successful ListFoundationModels events followed by high-cost model invocations by IAM users.
      technique_id: T1526
      data_needed:
        - AWS CloudTrail logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source document identifies this sequence as indicative of malicious activity.
  mitigation_plan:
    - priority: immediate
      action: Identify and rotate long-term IAM access keys used for Bedrock workloads.
      owner: IT Operations
      addresses: T1078.004
      evidence: Rule notes suggest migrating to IAM roles.
---

LLMjacking involves threat actors gaining access to cloud environments and utilizing stolen long-term IAM credentials (AKIA* access keys) to abuse AI services. In the context of Amazon Bedrock, attackers prioritize identifying available foundation models for potential exploitation to run high-volume or high-cost model inference. This activity is notable because legitimate production workloads utilizing Bedrock typically operate under temporary IAM roles, making the use of long-term user keys for discovery and invocation highly irregular. Defenders should monitor for patterns where the same access key performs enumeration followed immediately by model invocation. This activity indicates a potential compromise of IAM credentials and an attempt to leverage the organization's cloud resources for unauthorized AI model consumption at the account owner's expense.

## Impact

LLMjacking can result in significant financial impact due to high-volume model inference costs. Furthermore, it indicates that a threat actor has successfully gained Initial Access via compromised credentials, potentially allowing for broader exploitation of other AWS services such as S3 or Secrets Manager if the IAM user has excessive permissions.

## Recommendation

- Monitor AWS CloudTrail logs for the sequence of ListFoundationModels followed by InvokeModel, InvokeModelWithResponseStream, Converse, or ConverseStream by the same access key within 15 minutes.
- Prioritize auditing of all existing long-term IAM user access keys, enforcing rotation, and migrating Bedrock workloads to IAM roles with short-lived credentials.
- Investigate the source IP and user agent associated with any long-term key performing Bedrock operations to identify potential unauthorized access or credential exposure.
- Restrict the usage of long-term keys for AI services through Service Control Policies (SCPs) where business requirements permit.
