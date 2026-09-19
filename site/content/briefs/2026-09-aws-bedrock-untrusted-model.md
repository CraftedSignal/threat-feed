---
title: Detection of Unauthorized AWS Bedrock Model Import and Deployment
slug: 2026-09-aws-bedrock-untrusted-model
description: Unauthorized importation or deployment of AI models in AWS Bedrock can facilitate a supply-chain compromise by introducing backdoored or poisoned artifacts into an organization's inference pipeline.
date: "2026-09-19T13:29:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - bedrock
  - llm
  - persistence
vendors:
  - Amazon
products:
  - AWS Bedrock
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1525
    technique_name: Implant Internal Image
    evidence: Adversaries who can import a backdoored or poisoned model - or register an untrusted marketplace endpoint - can influence the output of any downstream application that invokes that model, constituting a supply-chain compromise.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/bedrock/latest/APIReference/API_CreateModelImportJob.html
  - https://docs.aws.amazon.com/bedrock/latest/userguide/model-import.html
rules:
  - title: AWS Bedrock Untrusted Model Imported or Marketplace Endpoint Registered
    description: Detects when an AWS Bedrock custom model is imported or deployed, or when a marketplace model endpoint is created or registered, potentially indicating unauthorized supply-chain compromise.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1525
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy rule to monitor for unauthorized Bedrock model imports.
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID c435defe-8438-4d5a-b4d0-86ab0faf9a49
  enrichment_needed:
    - item: Approved Bedrock service roles and S3 sources
      owner: CTI
      reason: To reduce false positives for authorized MLOps workflows.
      evidence: False positive analysis section
  hunt_leads:
    - lead: Search for recent successful CreateModelImportJob calls by non-service account identities.
      technique_id: T1525
      data_needed:
        - AWS CloudTrail logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Triage and analysis section
  mitigation_plan:
    - priority: immediate
      action: Restrict permissions for bedrock:CreateModelImportJob to authorized roles only.
      owner: IT Operations
      addresses: T1525
      evidence: Response and remediation section
---

Adversaries targeting cloud environments may attempt to gain persistence and influence machine learning pipelines by importing unauthorized model artifacts into AWS Bedrock. By utilizing Bedrock APIs such as `CreateModelImportJob`, `CreateCustomModelDeployment`, `CreateMarketplaceModelEndpoint`, or `RegisterMarketplaceModelEndpoint`, an attacker can introduce a backdoored or poisoned model into the organization's environment. Once deployed, these malicious models can be invoked by downstream applications, allowing the attacker to manipulate outputs, conduct data exfiltration, or maintain persistent unauthorized access. Defenders should monitor for these API calls to ensure all model onboarding aligns with approved internal training and validation pipelines, specifically verifying the provenance of S3-based artifacts and the authorization of the invoking principal.

## Impact

Successful exploitation results in a supply-chain compromise where poisoned models are utilized for inference in production applications. This can lead to manipulated decision-making, unauthorized data processing, and potential persistent control over AI-driven workflows. Organizations are advised to audit all current Bedrock model imports and marketplace endpoints to verify their origin.

## Recommendation

- Enable logging for `CreateModelImportJob`, `CreateCustomModelDeployment`, `CreateMarketplaceModelEndpoint`, and `RegisterMarketplaceModelEndpoint` via AWS CloudTrail to support the provided detection logic.
- Implement IAM policies that restrict the ability to register or import Bedrock models to verified MLOps service roles and CI/CD automation principals.
- Establish a formal review process for all S3 buckets acting as sources for model imports to ensure they reside in organization-controlled infrastructure.
- Deploy the provided detection logic to identify unauthorized or anomalous model onboarding activity.
