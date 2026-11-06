---
brief_id: brief-2026-11-06-genai-hash-detection
event_id: brief-2026-11-06-genai-hash-detection
revision: 1
activity_at: "2026-11-06T21:01:52Z"
title: Detection of Cryptographic Hashes in Generative AI Prompts
slug: 2026-11-genai-hash-detection
description: The security_ai integration for Elastic enables the detection of hex-encoded cryptographic hashes within GenAI prompts and completions, which may indicate credential exfiltration, offline cracking attempts, or encoded prompt injection payloads.
date: "2026-11-06T21:01:52Z"
lastmod: "2026-11-06T21:02:11Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - genai
  - exfiltration
  - cloud-security
  - machine-learning
  - Defense Evasion
  - LLM
  - Prompt Injection
vendors:
  - Amazon
  - OpenAI
products:
  - AWS Bedrock
  - OpenAI ChatGPT Enterprise
  - ChatGPT Enterprise
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110.002
    technique_name: Password Cracking
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Detects known credential formats appearing in GenAI prompt or completion text.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: Attackers embed base64 in prompts to smuggle instructions past content filters, exfiltrate data, or inject indirect prompt-injection payloads into model context.
references:
  - https://rules/integrations/security_ai/credential_access_genai_prompt_hash_string_detected.toml
  - https://owasp.org/www-project-top-10-for-large-language-model-applications/
  - https://attack.mitre.org/techniques/T1110/002/
  - https://atlas.mitre.org/techniques/AML.T0057/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/security_ai/credential_access_genai_prompt_hash_string_detected.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/security_ai/credential_access_genai_prompt_leaked_credential.toml
  - https://www.beyondtrust.com/blog/entry/aws-bedrock-security-guide-api-keys-detection-response
  - https://www.elastic.co/guide/en/security/current/prebuilt-rules-management.html
  - https://atlas.mitre.org/techniques/AML.T0068/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/security_ai/defense_evasion_genai_prompt_base64_encoded_content.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/security_ai/genai_assistant_response_high_confidence_malicious_content.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Configure monitoring for known credential patterns in GenAI invocation logs using the ES|QL logic identified in the source.
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID e3b1f8c4-7d2a-4e5b-9c1a-6f8d3b2e7a0c
  hunt_leads:
    - lead: Identify potential credential exposure in historical GenAI invocation logs
      technique_id: T1552
      data_needed:
        - gen_ai.input.messages
        - gen_ai.output.messages
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Credentials in the model input mean an application or user is sending secrets to the model.
  mitigation_plan:
    - priority: immediate
      action: Rotate and revoke any credentials identified as leaked in GenAI logs.
      owner: SOC
      addresses: T1552
      evidence: Either case warrants immediate credential rotation.
updates:
  - at: "2026-11-06T21:02:02Z"
    level: L2
    summary: added coverage for AWS Bedrock +1 products
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/security_ai/credential_access_genai_prompt_leaked_credential.toml
  - at: "2026-11-06T21:02:10Z"
    level: L1
    summary: added coverage for AWS Bedrock +1 products
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/security_ai/defense_evasion_genai_prompt_base64_encoded_content.toml
  - at: "2026-11-06T21:02:11Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/security_ai/genai_assistant_response_high_confidence_malicious_content.toml
---

The Elastic security_ai integration provides detection capabilities for identifying hex-encoded cryptographic digests (MD5, SHA-1, SHA-256, and SHA-512) within prompts sent to or completions returned by Generative AI services. The presence of these hashes in LLM interactions can serve as an indicator for several malicious activities: passing credential hashes for offline cracking, exfiltrating data fingerprints, or embedding encoded instructions as part of prompt injection payloads.

## Investigation
Security teams should investigate flagged hashes by examining `security_ai.hash_string.input_messages.strings` and `security_ai.hash_string.output_messages.strings`. Analysis should include reviewing the full conversation context for references to usernames, credentials, or structured exfiltration payloads, and verifying if the hash corresponds to known-bad IOCs.

## False Positives
Legitimate workflows such as security/forensics tools conducting threat intelligence lookups or CI/CD pipelines utilizing git commit SHAs, Docker image digests, or package checksums may trigger this rule. Contextual review is required to verify the nature of the hash.
