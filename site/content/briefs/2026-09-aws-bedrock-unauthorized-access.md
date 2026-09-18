---
title: Detection of Unauthorized Amazon Bedrock Foundation Model Access Attempts
slug: 2026-09-aws-bedrock-unauthorized-access
description: Detection of failed API calls attempting to enable Amazon Bedrock foundation model access, serving as a high-signal indicator for credential boundary-testing and potential LLMjacking.
date: "2026-09-18T19:37:56Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - bedrock
  - llmjacking
  - persistence
vendors:
  - Amazon
products:
  - Bedrock
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: A principal that is repeatedly denied when attempting these actions may be a compromised or under-privileged identity probing for the ability to unlock expensive models (LLMjacking) or to establish a durable ability to invoke models.
    confidence_band: high
rules:
  - title: AWS Bedrock Unauthorized Foundation Model Access Attempt
    description: Detects unauthorized attempts to enable account-level access to an Amazon Bedrock foundation model via failed API calls.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - cloudtrail
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy rule to detect denied Bedrock configuration attempts
      owner: Detection Engineering
      due: 48h
      evidence: Rule provides high-signal detection of unauthorized boundary-testing.
  hunt_leads:
    - lead: Search CloudTrail for identities attempting Bedrock configuration API calls that result in 403/AccessDenied
      technique_id: T1098
      data_needed:
        - CloudTrail logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Brief identifies these calls as indicators of LLMjacking reconnaissance.
  mitigation_plan:
    - priority: immediate
      action: Review IAM policies for Bedrock control-plane access
      owner: IT Operations
      addresses: Unauthorized Bedrock model access
      evidence: Source recommends constraining IAM permissions to only approved principals.
---

This threat brief focuses on detecting unauthorized attempts to enable account-level access to Amazon Bedrock foundation models. Attackers who compromise AWS identities may attempt to enable model entitlements or agree to model EULAs to unlock expensive foundation models for malicious usage, a technique often referred to as LLMjacking. By monitoring for denied control-plane API calls, defenders can identify compromised or under-privileged principals performing boundary-testing. This activity is critical to intercept, as successfully enabling these entitlements provides the necessary persistence for subsequent model invocation and abuse. While access-denied errors can stem from benign permission gaps in CI/CD pipelines or new employee onboarding, recurring unauthorized requests from unexpected source IPs or user agents are strong indicators of potential malicious reconnaissance.

## Impact

Successful exploitation of these Bedrock control-plane functions allows attackers to gain unauthorized access to LLM services, resulting in unauthorized costs, data exfiltration through model interaction, and potential abuse of generative AI capabilities. Organizations that do not monitor for these denied attempts risk missing the initial reconnaissance phase of an LLMjacking attack.

## Recommendation

Prioritize the investigation of unauthorized Bedrock control-plane activity to identify compromised credentials before they are successfully used to unlock models.

* Deploy the detection rule provided below to your SIEM to monitor for 'AccessDenied' events on Bedrock configuration APIs.
* Establish a baseline for users and roles authorized to perform 'PutFoundationModelEntitlement', 'PutUseCaseForModelAccess', and 'CreateFoundationModelAgreement' actions.
* Use CloudTrail logs to correlate denied Bedrock attempts with other suspicious IAM activity, such as permission enumeration or credential creation.
* Implement IAM Service Control Policies (SCPs) to restrict Bedrock management capabilities to specific, hardened administrator roles.
