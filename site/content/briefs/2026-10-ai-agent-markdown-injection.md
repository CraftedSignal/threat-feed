---
brief_id: brief-2026-10-26-ai-agent-markdown-injection
event_id: brief-2026-10-26-ai-agent-markdown-injection
revision: 2
activity_at: "2026-10-29T19:55:25Z"
revision_history:
  - revision: 2
    at: "2026-10-29T19:55:25Z"
    checksum: sha256:65f4968c505ab5fe432aead19ce45e2d9e9c0e089038f4b8f117faab6013572f
    summary: added coverage for Codex +1 products
    changed_fields:
      - action_plan
      - lastmod
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://www.darkreading.com/threat-intelligence/ai-relay-service-openai-codex-claude-code-sandboxes
title: 'AI Coding Assistant: Indirect Prompt Injection via Local Markdown Files'
slug: 2026-10-ai-agent-markdown-injection
description: An indirect prompt injection technique exploits AI coding agents by planting malicious AGENTS.md files in user download directories to execute unauthorized commands or exfiltrate credentials.
date: "2026-10-26T22:06:41Z"
lastmod: "2026-10-29T19:54:33Z"
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
tags:
  - ai-security
  - prompt-injection
  - supply-chain
  - credential-hijacking
  - shadow-it
vendors:
  - OpenAI
  - Anthropic
products:
  - Codex
  - Claude Code
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The malicious plaintext file named AGENTS.md in a customer's downloads folder, disguised as engineering notes.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    subtechnique_id: T1204.002
    subtechnique_name: Malicious File
    evidence: When the coding agent is launched in that directory, it reads the instruction file as part of its project context.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: The planted file makes the agent rewrite its own configuration, opening itself up for an attacker.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The relay service uses fileless PowerShell or bash scripts to reconfigure AI CLI tools.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The relay service replaces user API credentials with relay-issued tokens that persist across reboots.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: The configuration changes turn off the CLIs execution sandbox and telemetry features.
    confidence_band: high
references:
  - https://www.darkreading.com/application-security/in-the-wild-attack-ai-agents-trust-markdown
  - https://www.darkreading.com/threat-intelligence/ai-relay-service-openai-codex-claude-code-sandboxes
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review AI agent deployment and usage policies to prohibit execution in user-writable directories.
      owner: SOC
      due: 48h
      evidence: Forever Security recommends treating the user's home-directory download location as hostile ground for agents.
    - action: Hunt for unauthorized instances of OpenAI Codex or Anthropic Claude Code CLIs in the environment.
      owner: SOC
      due: 24h
      evidence: Unauthorized relay service installs these tools to hijack enterprise workflows.
  hunt_leads:
    - lead: Search for the existence of 'AGENTS.md' files within the users' Downloads directory or common coding project workspaces.
      technique_id: T1204.002
      data_needed:
        - File system scan logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Forever Security found a malicious plaintext file named AGENTS.md in a customer's downloads folder.
    - lead: Identify endpoints executing PowerShell or bash commands that download content from non-standard or lookalike domains.
      technique_id: T1059
      data_needed:
        - Endpoint process creation logs (Sysmon EID 1 or Linux auditd)
        - Command line arguments including web-fetch utilities (Invoke-WebRequest, curl, wget)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The relay service uses a fileless script fetched from a lookalike domain via a one-line command.
  mitigation_plan:
    - priority: immediate
      action: Enable sandboxing and require manual approval gates for all AI agent actions.
      owner: IT Operations
      addresses: Indirect prompt injection via local files
      evidence: Forever Security recommends leaving approval gates and sandboxes enabled.
    - priority: immediate
      action: Implement application control policies to prevent the installation of unauthorized AI CLI tools.
      owner: IT Operations
      addresses: Unauthorized installation of AI tools
      evidence: The relay service relies on installing tools on enterprise systems to perform hijacking.
updates:
  - at: "2026-10-29T19:54:33Z"
    level: L1
    summary: added coverage for Codex +1 products
    sources:
      - dark-reading
    source_urls:
      - https://www.darkreading.com/threat-intelligence/ai-relay-service-openai-codex-claude-code-sandboxes
---

AI coding agents, such as OpenAI's Codex and Anthropic's Claude Code, are susceptible to an indirect prompt injection vector involving local markdown instruction files. When an agent is launched within a directory containing a malicious "AGENTS.md" file, the agent consumes the file as part of its project context and treats the contained text as trusted instructions. This allows an attacker to manipulate the agent's configuration, leading to unauthorized code execution, the installation of malicious packages (e.g., via NPM), or the exfiltration of sensitive credentials. As the agent's behavior is consistent with its intended design, there is no conventional software vulnerability to patch.

## Attack Chain

1. An attacker places a malicious "AGENTS.md" file in a user-accessible directory, typically the Downloads folder (~/Downloads).
2. The user navigates to the compromised directory using their terminal or IDE.
3. The user launches an AI coding agent within the directory.
4. The AI agent automatically parses the "AGENTS.md" file to interpret project-specific instructions or configuration.
5. The AI agent executes malicious commands contained within the "AGENTS.md" file.
6. The agent performs follow-on activities, such as modifying its local configuration, installing unauthorized packages, or accessing and exfiltrating login tokens.

## Impact

Successful exploitation allows for arbitrary command execution within the agent's context. Observed impacts include unauthorized installation of NPM packages and potential theft of login tokens.

## Recommendation

* Treat the user's Downloads directory (~/Downloads) as a hostile environment; strictly avoid running AI coding agents in this directory.
* Audit active AI agent configurations for unexpected changes or unknown directives.
* Implement and maintain approval gates for all actions taken by AI agents, including configuration modifications and package installations.
* If suspicious activity is detected, rotate all credentials and login tokens associated with the AI agent immediately.
* Enable sandbox environments for all AI agent operations to limit access to sensitive directories and system resources.
