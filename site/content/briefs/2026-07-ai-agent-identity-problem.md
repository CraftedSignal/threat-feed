---
title: The Identity Problem Hiding in AI Agent Deployments
slug: 2026-07-ai-agent-identity-problem
description: CrowdStrike highlights a critical identity management gap in AI agent deployments where current OAuth 2.1 tokens and JWT (RFC 9068) lack standardized mechanisms to represent an AI agent's instance identity, the user on whose behalf it acts, and their relationship, hindering fine-grained access controls, audit trails, and detection of out-of-scope actions.
date: "2026-07-13T02:47:44Z"
lastmod: "2026-07-16T03:39:58Z"
type: threat
types:
  - threat
severities:
  - low
exploited: true
tags:
  - ai
  - identity
  - cloud-security
  - zero-trust
vendors:
  - CrowdStrike
  - Anthropic
  - GitHub
  - Microsoft
  - OpenAI
  - Google
products:
  - OAuth 2.1
  - JWT (RFC 9068)
  - AI Agent Deployments
  - AI agents
  - Claude Code
  - github.com
  - OAuth access tokens
  - JWT format (RFC 9068)
  - OAuth tokens
  - GitHub
  - Kubernetes AI applications
  - OAuth
  - JWT
  - RFC 9068
  - Claude
  - OAuth access tokens (RFC 9068)
  - OAuth tokens (when used with AI agents)
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Without this information, organizations cannot enforce fine-grained access controls, produce meaningful audit trails, or detect when an agent is acting outside its intended scope.
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: Without this information, organizations cannot enforce fine-grained access controls, produce meaningful audit trails, or detect when an agent is acting outside its intended scope.
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/the-identity-problem-hiding-in-ai-agent-deployments/
updates:
  - at: "2026-07-13T09:08:48Z"
    level: L1
    summary: new vendor
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/the-identity-problem-hiding-in-ai-agent-deployments/
  - at: "2026-07-14T07:47:56Z"
    level: L1
    summary: new product
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/the-identity-problem-hiding-in-ai-agent-deployments/
  - at: "2026-07-15T05:53:28Z"
    level: L2
    summary: oauth access tokens version RFC 9068
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/the-identity-problem-hiding-in-ai-agent-deployments/
  - at: "2026-07-15T07:52:08Z"
    level: L2
    summary: oauth tokens version when used with AI agents
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/the-identity-problem-hiding-in-ai-agent-deployments/
  - at: "2026-07-16T03:39:58Z"
    level: L1
    summary: new product
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/the-identity-problem-hiding-in-ai-agent-deployments/
---

CrowdStrike has identified a significant and growing security challenge within enterprise AI agent deployments, focusing on the inadequacy of existing identity standards for autonomous AI operations. Unlike human users with clear roles, AI agents can act on behalf of multiple users, be dynamically instantiated, and invoke other agents without real-time human oversight. Current OAuth 2.1 tokens and the JWT standard (RFC 9068) were designed for single-principal scenarios and lack standardized fields to express an AI agent's unique instance identity, the specific user it represents, and the nuanced relationship between them. This deficiency means organizations cannot implement effective fine-grained access controls, generate comprehensive audit trails, or reliably detect when an AI agent operates beyond its intended scope, posing a fundamental risk that escalates with increased AI agent adoption. The issue is a conceptual problem with current identity frameworks, not an active exploitation campaign.

## Impact

The primary impact of this identity problem is the inability for organizations to implement and enforce robust security controls for AI agents. Without a standardized way to attribute actions to specific agent instances and the human principals they represent, it becomes impossible to establish fine-grained access policies, leading to potential over-privileging and unauthorized data access. Moreover, the lack of contextual identity information compromises audit trails, making it difficult to investigate incidents, establish accountability, and detect malicious or erroneous behavior. This situation creates a systemic security blind spot that could facilitate data breaches, compliance violations, and system compromise as AI agents gain more autonomy and access to sensitive enterprise resources.

## Recommendation

* Prioritize implementing robust identity governance for AI agents, as highlighted by the lack of standardization in current OAuth tokens and JWT (RFC 9068).
* Advocate for industry standards and solutions that provide granular identity context for AI agents, including agent instance identity, user identity, and the relationship between them.
* Develop internal policies and architectural patterns for AI agent deployments that mitigate the risks of insufficient identity context, focusing on strict least-privilege principles even without perfect identity information.
* Engage with security vendors and standards bodies to promote the development of new identity protocols or extensions to existing ones (like OAuth 2.1 and JWT) that adequately address the unique identity challenges of AI agents.
