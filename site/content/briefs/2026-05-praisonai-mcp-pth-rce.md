---
title: PraisonAI MCP Path Traversal to RCE via .pth Injection
slug: 2026-05-praisonai-mcp-pth-rce
description: PraisonAI's MCP server is vulnerable to path traversal leading to arbitrary code execution by writing a Python `.pth` file into the user's site-packages directory, triggered via poisoned LLM contexts or unauthenticated HTTP-stream transports due to unvalidated kwargs in the dispatcher and lack of containment checks in file-handling tools.
date: "2026-05-11T13:59:36Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - code-execution
  - prompt-injection
  - mcp
vendors:
  - PraisonAI
products:
  - MCP (Model Context Protocol) server
affected_os:
  - Windows 11
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-9mqq-jqxf-grvw
rules:
  - title: Detect PraisonAI MCP Path Traversal via rules.create
    description: Detects path traversal attempts in the PraisonAI MCP server through the rules.create tool by monitoring for rule names containing '..'.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
      - T1190
    data_sources:
      - process_creation
      - windows
  - title: Detect PraisonAI MCP .pth File Creation in site-packages
    description: Detects the creation of .pth files in the user's site-packages directory, a common technique for escalating privileges via code injection.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
      - T1547.009
    data_sources:
      - file_event
      - windows
  - title: Detect PraisonAI MCP workflow.show Accessing Sensitive Files
    description: Detects use of the workflow.show tool to access sensitive files outside the intended workflow directories.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

PraisonAI's MCP (Model Context Protocol) server registers four file-handling tools by default: `praisonai.rules.create`, `praisonai.rules.show`, `praisonai.rules.delete`, and `praisonai.workflow.show`. Each accepts a path or filename string from MCP `tools/call` arguments and joins it onto `~/.praison/rules/` (or accepts an absolute path for `workflow.show`) without proper validation. The JSON-RPC dispatcher passes `params["arguments"]` without validating against the advertised input schema. This allows an attacker to write arbitrary files by escaping the rules directory, leading to arbitrary code execution via Python `.pth` injection into the user site-packages directory. The vulnerability can be exploited via LLMs with poisoned context, unauthenticated HTTP-stream transports, or prompt injection. No operator misconfiguration is required to trigger the vulnerability.

## Attack Chain

1. An attacker poisons the context of an LLM connected to a PraisonAI MCP server through attacker-controlled web content, documents, or emails.
2. The user interacts with the LLM, asking it to summarize or analyze the poisoned content, which contains a crafted command.
3. The LLM, under prompt injection, crafts a `tools/call` request to the MCP server, targeting `praisonai.rules.create` with a malicious `rule_name`.
4. The crafted `rule_name` includes path traversal sequences (e.g., `../../`) to write a file outside the intended rules directory.
5. The MCP server's `rules.create` handler, lacking containment checks, writes the file to a location such as the user's site-packages directory (e.g., `~/.local/lib/python3.14/site-packages/evil.pth`).
6. The written file is a Python `.pth` file containing an `import os; os.system("malicious_command")` statement.
7. The next time the user starts a Python interpreter (including the `praisonai` CLI), the `.pth` file is processed, executing the attacker's arbitrary code.
8. The attacker achieves arbitrary code execution with the user's privileges, potentially leading to data exfiltration, system compromise, or lateral movement.

## Impact

Successful exploitation allows an attacker to achieve arbitrary code execution on the victim's machine. This can lead to data exfiltration, installation of malware, or further compromise of the system. The vulnerability affects any user running a PraisonAI MCP server connected to an LLM without proper input validation, and the default configuration of the HTTP-stream transport exposes the server to local attacks without requiring authentication. The impact is significant as it can compromise the user's entire system and any data accessible to the user account.

## Recommendation

*   Apply input validation and containment to all file-handling tools. Specifically, implement checks to prevent path traversal in `praisonai.rules.create`, `praisonai.rules.show`, and `praisonai.rules.delete` as detailed in the "Suggested fix" section of the advisory.
*   Enforce schema validation in the MCP dispatcher to ensure that `params["arguments"]` conforms to the expected schema, rejecting unknown properties and type mismatches.
*   Restrict the `workflow.show` tool to only accept paths within a designated workflow directory and reject absolute paths or any value containing `..`, as outlined in the "Suggested fix" section.
*   Deploy the Sigma rules provided in this brief to detect potential exploitation attempts and tune them for your environment.
*   Require authentication on non-loopback HTTP-stream binds to prevent unauthorized access to the MCP server when using `praisonai mcp serve --transport http-stream`.
