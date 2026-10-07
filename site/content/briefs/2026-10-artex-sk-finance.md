---
title: Threat Actor Leverages AI-Driven ARTEX Tooling to Target South Korean Financial Institutions
slug: 2026-10-artex-sk-finance
description: An unidentified, likely Chinese-speaking threat actor is targeting South Korean financial entities using the open-source ARTEX penetration testing framework managed by Large Language Models to conduct reconnaissance and data exfiltration.
date: "2026-10-07T16:46:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - financial-sector
  - ai-threat
  - exfiltration
  - lateral-movement
  - reconnaissance
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1583.003
    technique_name: 'Acquire Infrastructure: Virtual Private Server'
    evidence: The threat actor acquires infrastructure at multiple IP addresses to establish command-and-control operations.
    confidence_band: high
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588.007
    technique_name: 'Obtain Capabilities: Artificial Intelligence'
    evidence: The threat actor obtains and deploys ARTEX, an open-source Chinese-developed agentic penetration testing tool, to conduct attacks against South Korean financial sector organizations.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: The threat actor used multiple proxy IP addresses during the ARTEX-related activity.
    confidence_band: high
iocs:
  - type: ip
    value: 38.244.50.120
  - type: ip
    value: 101.53.80.20
  - type: ip
    value: 205.214.59.31
  - type: ip
    value: 124.155.252.63
  - type: ip
    value: 154.201.79.246
  - type: ip
    value: 23.248.249.90
  - type: ip
    value: 23.158.220.98
  - type: ip
    value: 103.248.148.84
  - type: ip
    value: 203.160.133.172
  - type: ip
    value: 209.209.85.38
ioc_counts:
  ip: 10
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block listed C2 and proxy IP addresses at network egress
      owner: SOC
      due: 24h
      evidence: IOC list provided in the report
---

CrowdStrike has identified a campaign targeting South Korean financial organizations that leverages a novel combination of traditional offensive tradecraft and agentic AI-driven penetration testing tools. The threat actor, likely Chinese-speaking and financially motivated, utilized the open-source ARTEX (Agentic Red Teaming and Exploitation) framework, an AI-based tool designed to automate pentesting tasks. The actor employed a multi-stage infrastructure architecture involving a primary C2 server and a secondary server hosting the ARTEX instance.

The campaign, active from late September to early October 2026, successfully breached internal systems, including loan progress inquiry services and mobile work-support systems. Intelligence gathered from actor-controlled open directories revealed Claude Code session histories, configuration files, and memory files, confirming the use of DeepSeek v4.1-flash as the underlying model for ARTEX automation. This campaign demonstrates a significant advancement in the integration of LLMs into adversarial workflows to conduct targeted reconnaissance and exploitation.

## Attack Chain

1. The attacker acquires virtual private server (VPS) infrastructure, including a primary control server in Hong Kong and a secondary infrastructure node at 38.244.50[.]120.
2. The attacker establishes proxy chains to hide the origin of C2 traffic, utilizing multiple IP addresses listed as proxy nodes.
3. The ARTEX agentic framework is deployed and configured on the secondary server to interact with DeepSeek v4.1-flash via API endpoints.
4. The attacker uses Claude Code session scripts to input Chinese-language penetration testing prompts into the ARTEX instance.
5. The ARTEX agent executes automated reconnaissance against targeted South Korean financial network services.
6. The attacker leverages discovered vulnerabilities to access internal services such as loan progress portals and mobile support systems.
7. Sensitive organizational data is staged and exfiltrated from the compromised financial systems to actor-controlled infrastructure.

## Impact

The campaign successfully breached multiple South Korean financial organizations. Observed compromises include internal loan inquiry services and employee mobile work-support systems. If successful, the attack results in the exfiltration of sensitive financial and employee data, which likely serves as a precursor to monetization via extortion or the sale of stolen PII and financial records. The number of affected organizations remains unconfirmed, but the targeting suggests a coordinated effort to harvest high-value financial assets.

## Recommendation

1. Block all traffic to the known C2 and proxy IP addresses identified in the IOC list at your perimeter firewall and web proxy.
2. Monitor network egress logs for connections to known AI API endpoints or unauthorized agentic AI tool infrastructure.
3. Conduct threat hunting across internal financial application logs for anomalous queries or high-frequency automated interactions originating from unexpected internal or external sources.
4. Implement strict access control lists for loan processing and employee support systems to restrict access to authenticated, known corporate IP ranges.
5. Deploy enhanced monitoring for infrastructure staging activity, specifically identifying directories or files containing session logs for automated coding or pentesting tools.
