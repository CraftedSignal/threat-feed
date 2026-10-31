---
brief_id: brief-2026-10-28-railway-secret-compromise
event_id: brief-2026-10-28-railway-secret-compromise
revision: 2
activity_at: "2026-10-31T03:18:47Z"
revision_history:
  - revision: 2
    at: "2026-10-31T03:18:47Z"
    checksum: sha256:c2995fa25c694e9933976f1502095d5a149f6fdc020aae6e7dbea1b4ca92f029
    summary: added coverage for Fireworks AI (platform) +8 products
    changed_fields:
      - action_plan
      - affected_products
      - affected_vendors
      - content
      - iocs
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - summary
      - tags
      - title
      - ttps
      - updates
    source_urls:
      - https://www.wiz.io/blog/black-october-for-ai-developer-platforms
title: 'Black October: Agentic Attacks and LLMJacking on AI Developer Platforms'
slug: 2026-10-railway-secret-compromise
description: A coordinated wave of attacks against at least nine AI developer platforms has enabled mass LLMJacking, where stolen API keys are abused for large-scale inference traffic and resold via illicit markets.
date: "2026-10-28T05:35:31Z"
lastmod: "2026-10-31T03:17:27Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: No atomic validation required; remediation is administrative/operational.
tags:
  - credential-access
  - cloud
  - account-compromise
  - llmjacking
  - cloud-security
  - supply-chain-attack
  - ai-security
vendors:
  - Railway
  - Fireworks AI
  - Andromeda
  - Zeabur
  - Lightning AI
  - OpenCode
  - Warp
  - CommandCode
  - Northflank
products:
  - Railway
  - Fireworks AI (platform)
  - Andromeda (platform)
  - Zeabur (platform)
  - Lightning AI (platform)
  - OpenCode (platform)
  - Railway (platform)
  - Warp (platform)
  - CommandCode (platform)
  - Northflank (platform)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: The developer platform Railway urges all users to revoke secret keys after cyberattack.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Fireworks, Zeabur, and Lightning all attribute their incident root causes to credential access.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Railway so far has shared they believe the initial access was via 'privilege escalation in our build infrastructure'.
    confidence_band: high
references:
  - https://techcrunch.com/2026/10/22/developer-platform-railway-urges-all-users-to-revoke-secret-keys-after-cyberattack
  - https://www.wiz.io/blog/black-october-for-ai-developer-platforms
iocs:
  - type: ip
    value: 23.106.46.239
  - type: ip
    value: 38.246.114.118
  - type: domain
    value: llm-routing.com
  - type: domain
    value: xingjiabiapi.org
ioc_counts:
  domain: 2
  ip: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - DevOps
    - Cloud Security
  immediate_actions:
    - action: Force rotation of all Railway-managed secrets and environment variables.
      owner: DevOps
      due: 24h
      evidence: Railway platform instructions to all users to revoke keys.
    - action: Review and rotate all API keys used for AI/ML inference services stored in developer platform CI/CD pipelines.
      owner: Cloud Security
      due: 24h
      evidence: All public reports highlight targeted exploitation, explicitly hunting stored environment variables.
  hunt_leads:
    - lead: Identify unauthorized access to services linked to Railway secrets
      technique_id: T1552.001
      data_needed:
        - Cloud provider access logs (AWS/GCP/Azure)
        - Third-party API access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Keys were compromised; unauthorized use of these keys is the primary risk.
    - lead: Search for high volumes of InvokeModel or Bedrock API calls originating from unusual proxy or residential IP ranges.
      technique_id: T1078
      data_needed:
        - Cloud provider audit logs (e.g., AWS CloudTrail)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The actor made approximately 800k Bedrock calls... from a residential address and then, overnight, from a Level 3 hosting address.
  mitigation_plan:
    - priority: immediate
      action: Revoke and rotate all existing Railway secrets
      owner: DevOps
      addresses: Railway secret key compromise
      evidence: Vendor instruction to revoke secret keys.
    - priority: immediate
      action: Apply IAM constraints to restrict Bedrock inference profiles to specific regions.
      owner: Cloud Security
      addresses: Account quota exhaustion and LLMJacking
      evidence: Because global routing spread the load across regions, only about 6% of calls were throttled.
updates:
  - at: "2026-10-31T03:17:27Z"
    level: L2
    summary: added coverage for Fireworks AI (platform) +8 products
    sources:
      - wiz
    source_urls:
      - https://www.wiz.io/blog/black-october-for-ai-developer-platforms
---

Throughout October 2026, at least nine AI developer platforms - Fireworks AI, Andromeda, Zeabur, Lightning AI, OpenCode, Railway, Warp, CommandCode, and Northflank - disclosed security incidents. Attackers are actively targeting stored environment variables and API keys to perform "LLMJacking," a technique involving the unauthorized use of high-cost AI inference services. Observed activities include key validation, quota enumeration via Boto3 scripts, and high-volume inference calls routed through multiple regions to evade throttling. Illicit resellers, notably identified as "momo" and "Xingjiabi," have been observed leveraging infrastructure associated with the stolen credentials.

## Attack Chain
1. Initial Access: Attackers gain access to developer platforms through credential theft, third-party vendor dependencies, or legacy system vulnerabilities.
2. Credential Harvesting: Attackers hunt for stored environment variables, specifically those granting access to AI services like Amazon Bedrock.
3. Key Validation: Stolen keys are tested using automated, low-volume "InvokeModel" calls from residential proxy IPs.
4. Quota Enumeration: Attackers use Boto3-based scripts from hosting infrastructure to enumerate Bedrock and EC2 quotas, identifying account limits.
5. Traffic Flooding: Automated scripts initiate large-scale inference requests (reaching millions of calls) using stolen keys.
6. Evasion: Traffic is distributed across multiple cross-region inference profiles to bypass service throttling.
7. Monetization: Stolen access is integrated into public LLM resale platforms for commercial exploitation.

## Impact
Observed impacts include the theft of cryptocurrency keys, unauthorized consumer billing ranging from hundreds to thousands of dollars per incident, and the exhaustion of cloud service quotas. Two specific cases analyzed by Wiz documented ~2.5 million combined inference calls, resulting in an estimated $100k+ in unauthorized service costs.

## Recommendation
- Rotate all API keys and environment variables stored in developer platforms that disclosed incidents during October 2026.
- Implement strict IAM policies for AI services (e.g., AWS Bedrock) that restrict cross-region inference profiles and enforce regional limitations to reduce the blast radius of stolen keys.
- Establish monitoring for anomalous spikes in API calls, particularly for high-cost models like Claude Opus.
- Audit existing infrastructure for "shadow AI" and ensure no hardcoded credentials exist within build infrastructure or configuration files.
