---
title: New Agent Skills Installation Attempt Via Node.EXE
slug: 2026-07-node-agent-skills-install
description: A new detection identifies the use of `npx skills add` commands via `node.exe` on Windows systems, a potentially abusable mechanism for attackers to install malicious AI agent skills or 'skill worms' that can execute arbitrary commands and infect infrastructure.
date: "2026-07-03T13:57:46Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ai
  - node.js
  - supply-chain
  - attack.execution
  - attack.t1059.007
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects the attempt to install new skills for AI agents using the 'npx skills' command.
    confidence_band: high
references:
  - https://blog.lukaszolejnik.com/supply-chain-risk-of-agentic-ai-infecting-infrastructures-via-skill-worms/
  - https://github.com/vercel-labs/skills/blob/1f7fbc8d0e49c4e0601d364696bd1bdd15e80967/README.md
  - https://opensourcemalware.com/blog/clawdbot-skills-ganked-your-crypto
  - https://promptintel.novahunting.ai/molt
rules:
  - title: New Agent Skills Installation Attempt Via Node.EXE
    description: Detects the attempt to install new skills for AI agents using the 'npx skills' command, which could be abused to inject malicious commands executed by the agent.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

This brief details a detection for the `npx skills add` command executed via `node.exe` on Windows, a vector identified as a potential supply chain risk in the emerging field of AI agents. Threat actors could exploit this legitimate functionality, designed to enhance AI agents like Claude Code or Cursor with new capabilities, by injecting malicious commands into newly installed skills. These "skill worms" could then be executed by the AI agent, leading to unauthorized actions, data exfiltration, or infrastructure compromise. The detection, first published on 2026-07-01, highlights the importance for organizations to monitor and regulate the installation of AI agent skills, especially given the rising concerns about the integrity and security of AI tooling. This activity, while sometimes legitimate, warrants careful scrutiny due to its high potential for abuse by malicious actors seeking to leverage AI systems for nefarious purposes.

## Impact

The successful exploitation of this mechanism could lead to severe consequences for organizations leveraging AI agent tooling. By installing malicious "skills," attackers could gain the ability to execute arbitrary commands within the AI agent's environment, potentially leading to unauthorized data access, intellectual property theft, or further lateral movement within the compromised network. References indicate the risk of "infecting infrastructures via skill worms" and instances where "crypto" was "ganked," implying financial loss and broader system compromise. The severity of impact depends directly on the privileges and access of the compromised AI agent, which could range from individual user data compromise to widespread network infection if the agent has elevated permissions or broad system access.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM solution and configure it for Windows `process_creation` logs.
*   Enable comprehensive `process_creation` logging on all Windows endpoints to ensure the Sigma rule can effectively monitor `node.exe` executions.
*   Implement strict policies regarding the installation and vetting of AI agent skills within your environment, reviewing any "skills" installed by the `npx skills add` command.
*   Tune the provided Sigma rule based on your organization's specific policies regarding the authorized use of AI agent tooling to reduce false positives while maintaining detection efficacy.
