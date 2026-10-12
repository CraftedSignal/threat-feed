---
title: 'CVE-2026-108953: OS Command Injection in mac-shell-mcp'
slug: 2026-10-mac-shell-mcp-injection
description: The mac-shell-mcp package before version 2.0.0 is vulnerable to OS command injection via malicious prompt manipulation of execute_command arguments, allowing unauthorized code execution.
date: "2026-10-12T13:43:09Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mac-shell-mcp:mac-shell-mcp:*:*:*:*:*:*:*:*
tags:
  - injection
  - rce
  - mcp
  - mac-shell-mcp
products:
  - mac-shell-mcp (< 2.0.0)
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The package contains an OS command injection vulnerability that allows MCP clients to bypass the command whitelist by injecting shell metacharacters into execute_command arguments.
    confidence_band: high
cves:
  - id: CVE-2026-108953
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108953
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade mac-shell-mcp to 2.0.0 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-108953 disclosure
  mitigation_plan:
    - priority: immediate
      action: Update mac-shell-mcp to 2.0.0
      owner: IT Operations
      addresses: CVE-2026-108953
      evidence: NVD vulnerability details
---

The mac-shell-mcp library, used for Model Context Protocol (MCP) interactions, contains a critical OS command injection vulnerability identified as CVE-2026-108953. This vulnerability exists in versions prior to 2.0.0 and stems from improper sanitization of arguments passed to the execute_command function. MCP clients, which rely on this server component to execute shell commands, can be coerced by malicious prompts to execute unauthorized commands. An attacker can inject shell metacharacters, such as semicolons, into arguments intended for approved commands (e.g., pwd), effectively bypassing the established command whitelist. Successful exploitation results in arbitrary code execution with the permissions of the user running the MCP server process, posing a significant risk in environments where LLMs or external agents interact with local system resources.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the host machine running the mac-shell-mcp server. This can lead to full system compromise, data exfiltration, or the establishment of persistent backdoors depending on the privileges assigned to the user running the service. The vulnerability affects all deployments of mac-shell-mcp version 2.0.0 and earlier.

## Recommendation

- Upgrade mac-shell-mcp to version 2.0.0 or later immediately to patch the vulnerable execute_command input sanitization logic.
- Review all MCP server implementations for exposure to untrusted user input or external prompt injections that might invoke local shell commands.
- Ensure the user account running the MCP server has the principle of least privilege applied, restricting its ability to modify system-level files or reach sensitive data.
