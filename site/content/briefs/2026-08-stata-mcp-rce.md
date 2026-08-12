---
title: Stata-MCP Unsanitized Package Argument Command Injection
slug: 2026-08-stata-mcp-rce
description: The ado_package_install tool in stata-mcp fails to sanitize user-provided package names, allowing attackers to inject newline characters and execute arbitrary OS commands via the Stata REPL.
date: "2026-08-12T22:48:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - command-injection
  - stata-mcp
products:
  - stata-mcp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Because Stata supports a shell escape command, this leads to full OS-level arbitrary command execution.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-49m4-vp58-wgc9
---

The Stata-MCP server is vulnerable to a command injection vulnerability (CVE-2026-55071) within the `ado_package_install` tool, specifically in the `SSC_Install.install()` method. By failing to validate or sanitize the `package` argument, the tool allows an attacker to inject newline characters followed by arbitrary Stata commands. Because Stata provides a native `shell` escape mechanism, these injected commands can be elevated to OS-level arbitrary code execution (RCE). The vulnerability is critical because the affected tool is registered in the default `all` profile, meaning it is exposed to any caller - including AI agents or external clients - without requiring additional configuration. The existing `GuardValidator` mechanism is bypassed because it is not invoked during the ado-install code path, leaving installations prior to version 1.19.0 fully exposed.

## Attack Chain

1. Attacker identifies access to the Stata-MCP server, potentially via an exposed AI-agent interface or API endpoint.
2. Attacker crafts a JSON-RPC request targeting the `ado_package_install` tool.
3. Attacker embeds the malicious payload into the `package` argument, specifically including `\n` to terminate the intended `ssc install` command.
4. The Stata-MCP server receives the input and passes the unsanitized `package` string directly to `SSC_Install.install()`.
5. The method interpolates the string into a command buffer, which is subsequently passed to the `StataController`.
6. `StataController` uses `pexpect.sendline()` to write the multi-line string directly to the Stata REPL process.
7. The Stata REPL executes the intended command, followed immediately by the attacker's injected `shell` command.
8. OS command execution occurs with the privileges of the system user running the Stata-MCP server.

## Impact

Successful exploitation results in full OS-level command execution with the privileges of the Stata-MCP service user. This allows attackers to perform unauthorized data exfiltration, establish persistence on the host, move laterally within the network, or perform further local exploitation. Given the prevalence of AI agents interacting with such tools, this vulnerability poses a high risk to environments integrating Stata-MCP into automated workflows.

## Recommendation

* Upgrade `stata-mcp` to version 1.19.0 or later to patch the input sanitization flaw.
* Audit logs for calls to `ado_package_install` that contain newline characters or shell-related keywords such as "shell", "!", or "unixcmd".
* Isolate the Stata-MCP server process using containerization or restricted service accounts to minimize the potential impact of successful RCE.
* Implement strict request validation at the MCP gateway if upgrading is not immediately possible.
