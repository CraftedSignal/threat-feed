---
brief_id: brief-2026-11-21-ai-supply-chain-leaks
event_id: brief-2026-11-21-ai-supply-chain-leaks
revision: 1
activity_at: "2026-11-21T23:13:58Z"
title: AI Supply Chain Privacy and Security Deficiencies
slug: 2026-11-ai-supply-chain-leaks
description: Large-scale research using two million canary tokens across AI inference brokers and model providers identified systemic plaintext data leakage, unauthorized scraping of sensitive information, and active compromise of infrastructure by third-party adversaries.
date: "2026-11-21T23:13:58Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Content verified against Ars Technica reporting and documented updates.
tags:
  - supply-chain
  - cloud-security
  - data-exfiltration
  - privacy-violation
vendors:
  - AtlasCloud
  - MiniMax
  - Novita
  - OpenRouter
  - StreamLake
  - Vercel
products:
  - AtlasCloud
  - MiniMax
  - Novita
  - OpenRouter
  - StreamLake
  - Vercel
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Multiple resellers in the inference marketplace that logged the prompts and somehow passed them along to people who used the credentials.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: The attackers who compromised one of the providers reused a couple hundred of the AWS keys... stolen bait keys were used tens of thousands of times in AWS API calls.
    confidence_band: high
references:
  - https://arstechnica.com/security/2026/11/a-leaky-ai-supply-chain-is-exposing-secret-user-data-at-an-alarming-rate/
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Security
  immediate_actions:
    - action: Audit all IAM credentials currently in use by automated AI-integrated systems to ensure they do not possess broad access to secrets or production cloud resources.
      owner: IT Security
      due: 48h
      evidence: Research identified stolen credentials used in AWS API calls to access parameter stores and S3 buckets.
  hunt_leads:
    - lead: Search for unusual API activity, including IAM user creation, from credentials historically passed to AI integration services.
      technique_id: T1078
      data_needed:
        - Cloud Provider API/Audit Logs (e.g., AWS CloudTrail)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Adversaries attempted to enable hosted models and added their own IAM users to maintain access.
  mitigation_plan:
    - priority: immediate
      action: Disable Zero Data Retention assumptions for AI brokers; treat all input data as plaintext exposure risks.
      owner: Development
      addresses: Data Leakage
      evidence: Research found that privacy flags like ZDR or 'no data collection' did not prevent scraping or interception.
---

## Overview

Security research by HD Moore (Dragos) conducted in late 2026 demonstrates widespread privacy and security failures within the AI inference ecosystem. By seeding two million unique, trackable canary secrets (AWS keys, URLs, and repository references) into prompts sent through various AI brokers and resellers, researchers documented three distinct threat vectors: direct compromise of hosting providers by external adversaries to siphon prompt data, unauthorized logging and scraping of user prompts by AI resellers, and failure of AI providers to honor 'Zero Data Retention' or 'no data collection' privacy settings.

## Attack Chain

1. User submits a prompt containing sensitive data (e.g., credentials or URLs) to an AI broker application.
2. The AI broker/router receives the plaintext prompt to determine the optimal inference provider.
3. The prompt is forwarded through multiple hops in the inference supply chain (resellers, model providers, and hosting infrastructures).
4. At each hop, providers log and store the plaintext prompt for varying durations, violating stated privacy policies.
5. Adversaries targeting the provider infrastructure siphon the decrypted prompts directly from the ingress point or logs.
6. Adversaries extract credentials from stolen prompts and immediately validate them against cloud service providers to gain unauthorized access.
7. Unauthorized entities scrape embedded URLs within the prompts days or months after the initial request, even when privacy flags were present.

## Impact

Observed impacts include the theft and active use of hundreds of AWS access keys to access S3 buckets, parameter stores, and secrets managers. Adversaries also demonstrated persistence by attempting to spawn hosted models and create IAM users within compromised environments. Prompts marked with privacy-preserving flags were frequently intercepted and scraped by both providers and external malicious actors.

## Recommendation

- Move sensitive AI inference workloads to on-premises servers or utilize direct contracts with first-tier providers that avoid intermediary routing where possible.
- Treat all prompts submitted to third-party AI services as public information; avoid including any credentials, internal URLs, or proprietary source code in AI prompts.
- Review egress logs and cloud management APIs for unauthorized access attempts or IAM user creation originating from infrastructure utilized by AI model providers.
- Audit existing IAM roles used by AI-integrated services and enforce strict least-privilege access, ensuring that even if a prompt is leaked, the credentials exposed have minimal blast radius.
