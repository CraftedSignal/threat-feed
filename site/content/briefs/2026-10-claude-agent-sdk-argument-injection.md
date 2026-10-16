---
title: Claude Agent SDK Argument Injection via resume Option
slug: 2026-10-claude-agent-sdk-argument-injection
description: The Claude Agent SDK for Python fails to validate the resume option, enabling an argument injection attack that allows arbitrary command execution via unauthorized MCP server configurations.
date: "2026-10-16T22:28:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:anthropic:claude-agent-sdk:*:*:*:*:*:*:*:*
vendors:
  - Anthropic
products:
  - claude-agent-sdk (< 0.2.121)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker who controlled the resume value could inject an --mcp-config flag defining a stdio MCP server, resulting in arbitrary command execution at CLI startup.
    confidence_band: high
cves:
  - id: CVE-2026-96620
references:
  - https://github.com/advisories/GHSA-h4mw-j7qp-8mwm
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96620
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade claude-agent-sdk to 0.2.121 or later
      owner: IT Operations
      due: 24h
      evidence: Users are advised to update to the latest version of the claude-agent-sdk package.
  mitigation_plan:
    - priority: immediate
      action: Sanitize and validate session ID inputs
      owner: Application Security
      addresses: CVE-2026-96620
      evidence: Exploitation required an application to pass untrusted input as the session ID to resume.
---

The Claude Agent SDK for Python contains a critical argument injection vulnerability (CVE-2026-96620) caused by improper validation of the `resume` option. When an application utilizes this SDK and passes untrusted user input as a session ID to the resume functionality, the underlying Claude CLI incorrectly parses the input. An attacker can supply a value beginning with a dash (`-`), which the CLI interprets as an additional command-line flag rather than a data string. By injecting the `--mcp-config` flag, an attacker can specify a malicious stdio-based Model Context Protocol (MCP) server configuration, leading to arbitrary code execution when the CLI initializes. This vulnerability effectively bypasses intended SDK permission controls, allowing execution in the context of the user running the agent.

## Impact

Successful exploitation allows for arbitrary command execution on systems running applications that integrate vulnerable versions of the Claude Agent SDK (< 0.2.121). This impacts any software or automation pipeline utilizing the SDK to manage sessions with user-supplied input, potentially leading to unauthorized access to host environments, sensitive data exfiltration, or persistence.

## Recommendation

* Update the `claude-agent-sdk` Python package to version 0.2.121 or later immediately.
* Audit applications using `claude-agent-sdk` to ensure that session ID or `resume` parameter inputs are strictly sanitized and validated against an allowlist before being passed to the SDK.
* Review process execution logs for applications utilizing the SDK to identify unexpected command-line arguments being passed to the `claude` CLI binary.
