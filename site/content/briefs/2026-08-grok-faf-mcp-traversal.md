---
title: Path Traversal Vulnerability in grok-faf-mcp
slug: 2026-08-grok-faf-mcp-traversal
description: The grok-faf-mcp MCP server contains an arbitrary file read vulnerability via inadequate path validation, allowing attackers to access sensitive host files by injecting path traversal sequences into tool arguments.
date: "2026-08-19T22:34:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mcp
  - path-traversal
  - information-disclosure
products:
  - grok-faf-mcp (<= 1.5.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An MCP client — or an LLM prompt-injected via attacker-controlled content ... can read any file the server process can read
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The server runs over stdio, so the read is reached by a crafted tool call
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-cc2g-gq8c-r332
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade grok-faf-mcp to version 1.5.3 or higher
      owner: IT Operations
      due: 24h
      evidence: Fixed in 1.5.3 by confining every caller-supplied path
  mitigation_plan:
    - priority: immediate
      action: Set FAF_ALLOWED_ROOTS to restrict file access to trusted directories
      owner: IT Operations
      addresses: Arbitrary local file read
      evidence: set FAF_ALLOWED_ROOTS (patched versions) to a single project directory for a hard directory boundary
---

The `grok-faf-mcp` package, a Model Context Protocol (MCP) server, contains an arbitrary local file read vulnerability in versions 1.5.2 and earlier. The flaw resides in several tools, including `refresh_faf`, `faf_score`, and `faf_read`, which resolve caller-supplied `path` arguments without strictly confining them to a designated project directory. By leveraging absolute paths or directory traversal sequences (e.g., `../`), a remote attacker - or an LLM agent subject to prompt injection - can escape the intended project context and read any file accessible to the server process. This poses a severe risk of credential theft, including SSH keys, cloud provider configuration files, and environment variables. The vulnerability was disclosed by Zhihao Zhang and addressed in version 1.5.3, which introduces path canonicalization and restricted access to defined project directories.

## Attack Chain

1. An attacker influences an LLM agent to interact with the vulnerable `grok-faf-mcp` server.
2. The attacker delivers a prompt injection payload containing a malicious file path argument (e.g., `../../../../../../etc/passwd` or `../../.ssh/id_rsa`).
3. The MCP server receives the tool call (e.g., `faf_read`) from the LLM client via stdio.
4. The internal `getProjectPath()` function fails to restrict the path, resolving the attacker-provided traversal to the filesystem root.
5. The server process opens the requested sensitive file based on the OS-level permissions of the user running the MCP process.
6. The server tool, such as `refresh_faf` or `faf_read`, transmits the contents of the target file back to the LLM agent as part of its response.
7. The attacker exfiltrates the sensitive data from the agent's output.

## Impact

Successful exploitation allows for unauthorized disclosure of sensitive host information, including SSH private keys, cloud service credentials, environment files, and system configuration data. This primitive can lead to full host compromise if the server process is executed with high-privilege credentials or if the disclosed information provides access to further infrastructure.

## Recommendation

* Upgrade `grok-faf-mcp` to version 1.5.3 or higher via `npm install -g grok-faf-mcp@1.5.3`.
* If an immediate upgrade is not possible, restrict the server execution environment by setting the `FAF_ALLOWED_ROOTS` environment variable to a single, hardened project directory to enforce a strict boundary.
* Audit MCP server logs for unexpected file path arguments that contain traversal patterns (`../`) or point to sensitive system directories.
* Audit the runtime permissions of the user account executing the MCP server process to ensure the principle of least privilege is applied, specifically limiting access to sensitive user directories like `.ssh` or `.aws`.
