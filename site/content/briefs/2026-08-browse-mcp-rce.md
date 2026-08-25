---
title: Arbitrary File Write in browse-mcp Leading to Host Code Execution
slug: 2026-08-browse-mcp-rce
description: The browse-mcp package is vulnerable to arbitrary file write via unsanitized path arguments in browser tools, allowing an attacker to achieve host code execution by overwriting critical system configuration files.
date: "2026-08-25T18:50:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary-file-write
  - path-traversal
  - rce
  - agent-security
products:
  - browse-mcp (<= 0.8.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker could supply an arbitrary save_dir together with a URL whose response body became the file contents, writing attacker-controlled bytes to any path the process can reach (for example ~/.bashrc, an autostart entry, or a cron file).
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker could supply an arbitrary save_dir together with a URL whose response body became the file contents, writing attacker-controlled bytes to any path the process can reach (for example ~/.bashrc, an autostart entry, or a cron file).
    confidence_band: high
cves:
  - id: CVE-2026-55557
references:
  - https://github.com/advisories/GHSA-m9mq-7m7q-xc6p
  - CVE-2026-55557
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade browse-mcp to version 0.8.2
      owner: IT Operations
      due: 24h
      evidence: Fixed in 0.8.2. Upgrade to browse-mcp 0.8.2.
  mitigation_plan:
    - priority: immediate
      action: Restrict the exposed tools with BROWSE_MCP_TOOLS to a set that excludes browser_download, browser_save_state, and browser_load_state
      owner: Security Engineering
      addresses: CVE-2026-55557
      evidence: Restrict the exposed tools with BROWSE_MCP_TOOLS to a set that excludes browser_download, browser_save_state, and browser_load_state
---

The browse-mcp package (versions <= 0.8.1) contains a critical path traversal vulnerability that permits arbitrary file writes on the host machine. This issue arises from the `browser_download`, `browser_save_state`, and `browser_load_state` functions, which fail to validate destination directory paths or file path arguments provided by MCP clients. An attacker operating as a malicious MCP client, or by utilizing indirect prompt injection against an autonomous agent, can specify absolute paths or use directory traversal characters (..) to write arbitrary data to restricted locations, such as bash configuration files, cron entries, or autostart directories. Furthermore, the `force_fetch` utility was discovered to ignore the `BROWSE_MCP_ALLOWED_ORIGINS` fence, allowing for unauthorized data retrieval. These flaws provide a direct pathway for host code execution. The vulnerability is addressed in browse-mcp version 0.8.2, which introduces path confinement and improved input sanitization.

## Attack Chain

1. An attacker identifies an autonomous agent or MCP client environment utilizing browse-mcp.
2. The attacker triggers an indirect prompt injection by serving a malicious URL to the agent's browser tool.
3. The agent or malicious client calls the `browser_download` or `browser_save_state` function.
4. The attacker provides a crafted `save_dir` or `path` argument containing directory traversal (e.g., ../../../home/user/.bashrc).
5. The `browser-mcp` service fetches content from the attacker-controlled source or writes provided state data.
6. The application performs the write operation at the destination path without path validation.
7. The attacker overwrites a critical configuration file to include malicious commands.
8. Upon file execution or shell initialization, the injected commands run, resulting in full host code execution.

## Impact

Successful exploitation allows for arbitrary file write, which can result in full host code execution (HCE). This impacts the security posture of any environment where an autonomous agent utilizes browse-mcp, as it bridges the gap between web-based data retrieval and host filesystem access. There is no indication of mass exploitation, but the vulnerability is highly severe in agentic workflows.

## Recommendation

* Immediately upgrade browse-mcp to version 0.8.2 or higher to implement mandatory path confinement.
* If upgrading is not immediately feasible, remove or disable the `browser_download`, `browser_save_state`, and `browser_load_state` tools within the `BROWSE_MCP_TOOLS` configuration.
* Audit application logs for abnormal path usage or tool calls involving directory traversal patterns (e.g., ".." or absolute paths) when invoking browser management tools.
* Define a hardened configuration by strictly controlling the `BROWSE_MCP_HOME` environment variable to ensure all state data is constrained to a known, non-sensitive directory.
