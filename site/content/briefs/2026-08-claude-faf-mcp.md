---
title: Arbitrary Local File Read and Write in claude-faf-mcp
slug: 2026-08-claude-faf-mcp
description: The claude-faf-mcp MCP server exposes arbitrary file read and write primitives through unconfined path parameters, allowing LLM-based prompt injection to access sensitive local files or modify system files.
date: "2026-08-19T22:34:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - mcp
  - path-traversal
  - arbitrary-file-read
  - arbitrary-file-write
products:
  - claude-faf-mcp (<= 5.7.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The server runs over stdio, so the read/write is reached by a crafted tool call (e.g. a prompt-injected agent processing attacker-controlled content).
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An MCP client, or an LLM prompt-injected via attacker-controlled content, can be made to read or write files outside the intended project context.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-rr55-jp92-8wp2
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade claude-faf-mcp to 5.7.2
      owner: IT Operations
      due: 24h
      evidence: Fixed in 5.7.2 by confining every caller-supplied path before any filesystem access
  mitigation_plan:
    - priority: immediate
      action: Set FAF_ALLOWED_ROOTS to a restricted project directory
      owner: IT Operations
      addresses: claude-faf-mcp (<= 5.7.1)
      evidence: If you cannot upgrade immediately, run the server only against trusted local projects, and set FAF_ALLOWED_ROOTS to a single project directory
---

The `claude-faf-mcp` package (versions 5.7.1 and earlier) contains a critical path traversal vulnerability in its Model Context Protocol (MCP) tools. The server process fails to confine user-supplied `path` arguments to a trusted project directory, instead resolving paths directly into the local filesystem. By providing absolute paths or directory traversal sequences like `../`, an attacker or a prompt-injected LLM can bypass intended project restrictions to read or write files anywhere the server process has operating system permissions. This vulnerability, identified during a security audit, permits unauthorized access to sensitive local credentials, including SSH keys, cloud configuration files (e.g., `~/.aws/credentials`), and `.env` files. The issue was remediated in version 5.7.2 by implementing strict path canonicalization and directory confinement guards in `safe-path.ts`.

## Attack Chain

1. An attacker influences an LLM agent to interact with the `claude-faf-mcp` server by hosting malicious content in a project file, ticket, or web page.
2. The LLM agent receives the content, triggering a malicious tool call to `faf_read` or `faf_write` via the MCP interface.
3. The attacker-controlled tool call includes a crafted `path` argument, such as `/home/user/.ssh/id_rsa` or `../../../../etc/passwd`.
4. The server's `getProjectPath()` function receives the path and processes it using `path.resolve()` without checking against a restricted project root.
5. The server executes the filesystem operation on the target path, as it assumes the request is within the legitimate `.faf` project context.
6. For `faf_read`, the server returns the contents of the unauthorized sensitive file to the LLM agent, where the attacker can then exfiltrate it.
7. For `faf_write`, the server overwrites or creates arbitrary files on the local disk using the permissions of the user running the MCP server.

## Impact

Successful exploitation results in arbitrary local file disclosure and unauthorized file modification. An attacker can access critical secrets, API keys, and environment variables stored on the host system. Furthermore, the ability to write files allows for potential persistence or lateral movement by overwriting configuration files or adding malicious scripts to accessible directories. The impact affects any developer or system running a vulnerable version of `claude-faf-mcp` in an environment where the agent processes untrusted, attacker-controlled data.

## Recommendation

* Upgrade `claude-faf-mcp` to version 5.7.2 or later immediately to apply the path confinement logic in `safe-path.ts`.
* If upgrading is delayed, configure the `FAF_ALLOWED_ROOTS` environment variable to restrict the server to a single, hardened project directory.
* Audit logs for unauthorized tool execution patterns or suspicious file paths (e.g., directory traversal strings `../` or common secret paths) passed to the MCP server.
* Ensure the MCP server process runs with the least privilege necessary, avoiding execution as a root or high-privilege user to minimize the impact of file system writes.
