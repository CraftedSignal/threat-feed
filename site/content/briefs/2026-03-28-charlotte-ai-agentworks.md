---
brief_id: brief-2026-03-28-charlotte-ai-agentworks
event_id: brief-2026-03-28-charlotte-ai-agentworks
revision: 2
activity_at: "2026-03-28T21:52:45Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:c5f668a3a7d7a1864f2947819eedcd412f9b8c47525dd56a5bfee971eb9b9a06
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: CrowdStrike Charlotte AI AgentWorks and Agentic SOAR for Automated Security Operations
slug: 2026-03-28-charlotte-ai-agentworks
description: CrowdStrike's Charlotte AI AgentWorks and Agentic SOAR enable agentic security operations by providing a hub for building and orchestrating AI-powered security agents, reducing manual workloads and accelerating AI adoption with free AI credits.
date: "2026-03-28T21:52:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
tags:
  - agentic-soc
  - ai
  - automation
  - soar
references:
  - https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/
rules:
  - title: Detect Amazon SageMaker Usage
    description: Detects usage of Amazon SageMaker which is integrated with Charlotte AI AgentWorks
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Amazon Bedrock Usage
    description: Detects usage of Amazon Bedrock which is integrated with Charlotte AI AgentWorks
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

CrowdStrike has introduced Charlotte AI AgentWorks and Charlotte Agentic SOAR to revolutionize security operations through AI-powered automation. Charlotte AI AgentWorks acts as a central hub for building and scaling security agents across diverse teams and environments. It integrates with AI models from Anthropic, NVIDIA, and OpenAI, leveraging services like Amazon Bedrock and Amazon SageMaker. Charlotte Agentic SOAR orchestrates these agents, automating time-intensive tasks and streamlining investigations. This new model aims to amplify human expertise with machine speed, shifting analysts from manual firefighting to strategic oversight. CrowdStrike is offering 50 free AI credits per month to encourage customer adoption and facilitate the transition to agentic operations.

## Attack Chain

This brief describes a product, not a threat actor or attack campaign. Therefore, there is no attack chain.

## Impact

The intended impact of Charlotte AI AgentWorks and Agentic SOAR is to reduce manual investigation workloads by 70%, restore more than 40 hours of team capacity per week, and achieve greater than 98% decision accuracy. Successful implementation should reshape the analyst experience by eliminating toil, accelerating outcomes, and helping teams seize an operating advantage in the AI era. Failure to adopt such systems could leave organizations vulnerable to AI-accelerated adversaries and eCrime breakout times that can be as fast as 27 seconds.

## Recommendation

*   Evaluate Charlotte AI AgentWorks and Agentic SOAR within your security operations to assess their potential impact on automation and efficiency (refer to the overview).
*   Utilize the offered 50 free AI credits per month to experiment with and deploy mission-ready agents across Falcon platform modules (refer to the "Activate Charlotte AI with Free Credits Today" section).
*   Design and implement automated workflows using the natural language processing capabilities of Charlotte AI, as described in the "Activate Charlotte AI with Free Credits Today" section.
