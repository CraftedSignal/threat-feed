---
brief_id: brief-2026-11-03-crowdstrike-claude-cowork
event_id: brief-2026-11-03-crowdstrike-claude-cowork
revision: 1
activity_at: "2026-11-03T09:35:37Z"
title: 'CrowdStrike and Anthropic: Claude Cowork Security Integration'
slug: 2026-11-crowdstrike-claude-cowork
description: CrowdStrike has introduced a native security integration with Anthropic’s Claude Cowork that deploys the Falcon Linux sensor inside agent virtual machines to mitigate supply chain and execution risks within isolated AI environments.
date: "2026-11-03T09:35:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - ai-security
  - endpoint-security
  - cloud-security
  - product-news
vendors:
  - Anthropic
products:
  - Claude Cowork
affected_os:
  - macOS
  - Windows
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-secures-ai-agents-inside-claude-cowork/
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - IT Operations
  hunt_leads:
    - lead: Identify workstation activity associated with the Claude Cowork virtual machine process
      technique_id: T1059.003
      data_needed:
        - Host-level process creation logs
        - Hypervisor or virtualization logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: When Claude Cowork executes code locally, it runs inside an isolated virtual machine on the user host.
  mitigation_plan:
    - priority: short_term
      action: Enroll in the beta program for CrowdStrike Falcon integration within Claude Cowork for macOS users.
      owner: IT Operations
      addresses: Claude Cowork
      evidence: This integration is now available in beta on macOS, with Windows support expected later in November.
---

CrowdStrike has partnered with Anthropic to provide runtime visibility and security for the Claude Cowork AI agent platform. Previously, code execution within Claude Cowork occurred inside an isolated virtual machine that served as a blind spot for host-based endpoint security sensors. By deploying a Falcon Linux sensor directly inside the Cowork VM, defenders can now monitor process, package, and network activity originating from the agent. This integration is currently in beta for macOS, with Windows support expected in late November 2026.

## Impact

The integration addresses the risk of AI agents inadvertently executing malicious code, such as compromised software packages, which could otherwise leverage mounted host folders to exfiltrate data without host-level visibility.

## Recommendation

* Inventory all workstations utilizing the Claude Cowork agent within the environment.
* Prepare for the beta deployment of the Falcon Linux sensor inside Claude Cowork virtual machines, beginning with macOS endpoints.
* Configure existing Falcon device management tools to support the forthcoming sensor deployment for the Windows platform, expected in late November 2026.
