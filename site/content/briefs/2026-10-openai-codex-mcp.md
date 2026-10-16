---
title: Detection of Unauthorized Model Context Protocol Tool Usage in ChatGPT Enterprise
slug: 2026-10-openai-codex-mcp
description: This threat brief details the potential for unauthorized data collection via Model Context Protocol (MCP) tools within OpenAI ChatGPT Enterprise, where attackers may leverage new or unusual connectors to exfiltrate organizational data from internal repositories.
date: "2026-10-16T16:21:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - genai
  - cloud
  - collection
  - ueba
vendors:
  - OpenAI
products:
  - ChatGPT Enterprise
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
    evidence: MCP tools can query external systems and pull organizational data into an agent session.
    confidence_band: high
references:
  - https://www.elastic.co/docs/reference/integrations/openai_chatgpt_enterprise
  - https://platform.openai.com/docs/compliance
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy alerting for new tool/user/org triplets in OpenAI ChatGPT Enterprise audit logs
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific fields (gen_ai.tool.name, user.email) for new term detection
  hunt_leads:
    - lead: Identify all unique MCP connector IDs currently in use across the organization
      technique_id: T1213
      data_needed:
        - openai_chatgpt_enterprise.codex_log.event_details.tool_meta.connector_id
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Tooling usage identifies unauthorized access vectors
---

Organizations utilizing OpenAI ChatGPT Enterprise are susceptible to data collection risks stemming from the misuse of Model Context Protocol (MCP) tools. MCP connectors enable AI agents to interact with external systems, such as source code repositories, collaboration platforms, and internal ticketing systems. If an attacker gains access to a user's session or leverages an unauthorized user account, they may configure or invoke malicious or unintended MCP tools to pull sensitive organizational data into the chat context for exfiltration. 

Defenders must differentiate between sanctioned engineering automation and anomalous behavior. The primary indicator of potential risk is the introduction of a "first-seen" tool, connector, or resource access pattern by a user within the enterprise environment. Monitoring these transitions allows security operations teams to identify when an actor begins querying an internal resource they have not previously interacted with, which is a key indicator of internal reconnaissance or exfiltration.

## Impact

The unauthorized use of MCP tools can lead to the exposure and exfiltration of sensitive corporate data stored in connected enterprise repositories. If an agent session is compromised or if an insider actor leverages these integrations, proprietary source code, internal communication logs, and sensitive customer or infrastructure metadata can be systematically pulled into an external AI session, potentially bypassing standard data loss prevention (DLP) controls.

## Recommendation

Detection engineering teams should focus on identifying the introduction of new organizational/user/tool combinations.

- Implement monitoring for the 'app_mcp_call' event action within OpenAI ChatGPT Enterprise audit logs.
- Establish a baseline of approved MCP connectors and tool names; alert on any tool call that does not match an entry in the organization's approved inventory.
- Review session logs associated with a 'first-seen' tool call for indicators of prompt injection, retrieval of sensitive data, or unusual volumes of data being pulled from resource IDs.
- Treat sessions involving unapproved MCP connectors as potential data exposure incidents; initiate an immediate review of the session history to identify the extent of information retrieved.
