---
title: Securing AI Agents and Governing Shadow AI
slug: 2026-04-securing-ai-agents
description: CrowdStrike is introducing new capabilities to secure AI agents and govern shadow AI across endpoints, SaaS, and cloud environments by providing detection and response (AIDR) for desktop AI applications, discovery of AI-related components, and runtime security for agents built in Microsoft Copilot Studio to combat attacks like living off the AI land (LOTAIL) by securing the agentic interaction layer.
date: "2026-03-30T06:41:52Z"
severities:
  - high
tags:
  - AI
  - agentic-soc
  - shadow-ai
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
references:
  - https://crowdstrike.com/en-us/blog/new-crowdstrike-innovations-secure-ai-agents-govern-shadow-ai/
rules:
  - title: Detect AI Application Execution via Command Line
    description: Detects the execution of common AI applications like ChatGPT, Gemini, or Copilot via command line, which can be an indicator of malicious activity or unauthorized usage.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: AI Discovery Tool Execution
    description: Detects execution of an AI discovery tool, which is an initial step to identifying and classifying AI-related components such as LLMs and MCP servers. This execution might be benign, but in the wrong hands, could be used for reconnaissance.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Organizations are rapidly adopting AI tools, deploying AI agents, and building AI-powered software, which introduces new attack surfaces. These new surfaces are often unprotected by traditional security controls. This rapid adoption of AI has led to the rise of shadow AI, where employees adopt AI tools without oversight and engineering teams deploy models and agents without adequate visibility and runtime protection. CrowdStrike is releasing new innovations across their Falcon platform to…
