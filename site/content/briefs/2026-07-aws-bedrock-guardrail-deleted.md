---
title: AWS Bedrock Guardrail Deleted
slug: 2026-07-aws-bedrock-guardrail-deleted
description: A detection rule has been developed for Amazon Bedrock that identifies the deletion of guardrails, indicating a potential attempt by an attacker or insider to disable AI model safety controls and facilitate unsafe or unauthorized responses.
date: "2026-07-27T16:48:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloud-security
  - defense-impairment
vendors:
  - Amazon
products:
  - AWS Bedrock
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Defense Impairment
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Detects deletion of an Amazon Bedrock guardrail, which may indicate attempts to remove model safety controls.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/bedrock/latest/APIReference/API_DeleteGuardrail.html
rules:
  - title: AWS Bedrock Guardrail Deleted
    description: Detects deletion of an Amazon Bedrock guardrail, which may indicate attempts to remove model safety controls and allow unsafe or unauthorized model responses.
    platform: sigma
    severity: medium
    tactics:
      - defense_impairment
    techniques:
      - T1562.001
    data_sources:
      - aws
      - cloudtrail
rules_count: 1
---

This brief describes the detection of a critical security event within Amazon Web Services (AWS) Bedrock, specifically the deletion of AI model guardrails. AWS Bedrock guardrails are integral security mechanisms designed to enforce responsible AI usage by filtering out harmful content, restricting specific topics, and ensuring adherence to safety policies. The `DeleteGuardrail` event, captured via AWS CloudTrail, signifies that an identity has deliberately removed these protective layers. While no specific threat actor or campaign is detailed, this action is a common tactic in the defense impairment phase of an attack, where adversaries seek to disable security features to achieve their malicious objectives, such as generating harmful content or exfiltrating sensitive data via a compromised AI model. Detecting such deletions is crucial for maintaining the integrity and safety of AI applications.

## Impact

The successful deletion of AWS Bedrock guardrails directly compromises the safety and ethical guidelines of deployed AI models. Without these controls, AI models could be manipulated to generate harmful, inappropriate, or unauthorized content, including misinformation, hate speech, or instructions for illegal activities. This loss of control can lead to reputational damage, regulatory non-compliance, and potentially legal repercussions for the organization. While this detection focuses on the act of deletion rather than a specific exploit, it represents a critical step towards enabling further malicious activities through the now unchecked AI model.

## Recommendation

* Deploy the Sigma rule "AWS Bedrock Guardrail Deleted" to your SIEM system to monitor for guardrail deletion events in your AWS environment.
* Ensure AWS CloudTrail logging is enabled for the `bedrock.amazonaws.com` service to capture `DeleteGuardrail` events.
* Review all instances of `DeleteGuardrail` events, especially those from unfamiliar or newly created identities, to differentiate legitimate administrative actions from potential malicious activity.
* Implement Identity and Access Management (IAM) policies with least privilege principles for Bedrock guardrail management, restricting `bedrock:DeleteGuardrail` permissions to only necessary roles.
