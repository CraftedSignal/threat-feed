---
brief_id: brief-2026-11-24-agentic-frameworks
event_id: brief-2026-11-24-agentic-frameworks
revision: 1
activity_at: "2026-11-24T10:48:54Z"
title: Defending against agentic offensive frameworks
slug: 2026-11-agentic-frameworks
description: Threat actors are increasingly using AI-driven agentic offensive frameworks to automate the identification and exploitation of internet-facing vulnerabilities at high speed and scale.
date: "2026-11-24T10:48:54Z"
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
tags:
  - ai
  - automation
  - threat-intelligence
  - defensive-strategy
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Agents start by mapping every device and service that's reachable.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The incidents involved automated identification and exploitation attempts across organisations' internet-facing services and assets in quick succession.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: 'Agentic attacks are exploiting low hanging fruit such as: credentials mistakenly committed to code repositories.'
    confidence_band: high
references:
  - https://www.ncsc.gov.uk/blogs/familiar-weaknesses-exploited-faster-defending-against-agentic-cyber-attacks
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
    - IT Operations
  hunt_leads:
    - lead: Identify bursts of requests from single sources to multiple obscure or legacy endpoints followed by unusually high error rates.
      technique_id: T1190
      data_needed:
        - Web access logs (status codes, URI stem)
        - Network traffic logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 'Agent activity tends to look different from human activity: bursts of requests followed by short thinking phases, a wide variety of endpoints and parameters (including garbage or example variants which would never work), and increased error rates.'
  mitigation_plan:
    - priority: immediate
      action: Audit and restrict internet access for legacy services and utilize identity-aware proxies.
      owner: IT Operations
      addresses: Public-facing asset exposure
      evidence: Services successfully compromised by agentic offensive frameworks are sometimes those that an organisation has forgotten about such as old websites and legacy equipment.
---

## Overview

Since September 2026, the NCSC has observed a rise in AI-assisted cyber attacks utilizing 'agentic offensive frameworks'. These tools, originally intended for authorized red teaming, are being repurposed by threat actors to automate the discovery and exploitation of internet-facing assets. Rather than exploiting novel vulnerabilities, these agents target known misconfigurations, technical debt, and weak authentication, including credentials left in code repositories and poorly secured APIs. The primary threat uplift is not new capability, but the speed, persistence, and low-cost nature of the automation, which allows agents to iterate rapidly based on feedback from system error messages.

## Attack Chain

1. Reconnaissance: Agents map all internet-reachable devices and services to identify potential entry points.
2. Vulnerability Discovery: Agents test for common weaknesses, including unpatched services, legacy equipment, and default credentials.
3. Initial Exploitation: Agents target misconfigurations (e.g., in infrastructure as code) or exposed credentials to gain a foothold.
4. Feedback Loop: Agents read error messages and system responses to learn from failed attempts and refine subsequent attack steps.
5. Post-Exploitation: Agents explore internal network segments, leveraging over-privileged credentials.
6. Persistence/Action: Agents maintain presence or conduct further actions using human-driven or automated methods.

## Recommendation

- Perform comprehensive asset discovery to identify and decommission legacy or forgotten internet-facing services.
- Restrict internet access to services by placing them behind identity-aware proxies using phishing-resistant authentication.
- Improve logging and correlation to detect non-human traffic patterns, specifically looking for bursts of requests followed by short thinking phases, high error rates, and requests across diverse endpoints.
- Sanitize error messages returned to users to prevent agents from using system feedback to tune their attacks.
- Deploy bot challenges on high-priority assets such as account login and inventory checkout flows.
- Enforce API-level rate limiting that considers behavioral signals (e.g., rapid failures or retries) rather than relying solely on IP-based blocking.
