---
title: Remote Code Execution in functype-mcp-server via Unsanitized MCP Tool Input
slug: 2026-09-functype-mcp-rce
description: The set_functype_version MCP tool in functype-mcp-server allows unauthenticated attackers to execute arbitrary code by passing a malicious package alias to pnpm, which the server subsequently executes via dynamic import.
date: "2026-09-10T00:51:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - mcp
  - nodejs
vendors:
  - Jordan Burke
products:
  - functype-mcp-server (1.4.3)
affected_os:
  - linux
  - windows
  - macos
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The server process dynamically imports an attacker-controlled JavaScript module, resulting in the execution of arbitrary JavaScript code.
    confidence_band: high
rules:
  - title: Detect Suspicious MCP Tool Input for set_functype_version
    description: Detects exploitation attempts against set_functype_version by monitoring for suspicious package aliases in the version parameter, such as file paths or URI schemes.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Patch functype-mcp-server to use input validation for the version argument.
      owner: IT Operations
      due: 24h
      evidence: Remediation provided in GHSA advisory.
  hunt_leads:
    - lead: Search for pnpm processes spawning from functype-mcp-server with unexpected arguments.
      technique_id: T1059.003
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source shows exploitation triggers via pnpm add with file paths.
  mitigation_plan:
    - priority: immediate
      action: Run MCP server in restricted environment.
      owner: IT Operations
      addresses: RCE vulnerability
      evidence: Vulnerability allows arbitrary file access and RCE if the process is compromised.
---

The `functype-mcp-server` tool `set_functype_version` (v1.4.3) is vulnerable to Remote Code Execution (RCE) because it fails to sanitize user input before passing it to the `pnpm add` command. An attacker can supply a specially crafted version string, such as `file:/path/to/malicious_package` or other npm-supported alias syntaxes, to force the server to install an arbitrary local or remote package as the `functype` dependency. Immediately following this installation, the server triggers `initDocsData(true)`, which dynamically imports the `functype/cli` module from the newly created installation path. This process executes any module-level JavaScript contained within the attacker's package with the full privileges of the MCP server process. This vulnerability is particularly dangerous for AI coding agents that automatically invoke MCP tools based on prompts, as it allows for indirect prompt injection to achieve full system compromise.

## Attack Chain

1. An attacker sends a `tools/call` MCP request for `set_functype_version` to an exposed MCP server.
2. The input `version` argument, containing a malicious alias like `file:/tmp/evil`, is accepted by the server without validation (line 120, `index.ts`).
3. The server constructs a package specifier string `functype@file:/tmp/evil` (line 123, `index.ts`).
4. The server executes `execFileSync("pnpm", ["add", spec], ...)` which installs the malicious directory as the `functype` package (line 125, `index.ts`).
5. The server process calls the `initDocsData(true)` function immediately after the installation finishes.
6. The server invokes `require.resolve("functype/cli")`, which resolves to the path of the newly installed attacker package.
7. The server calls `import()` on the resolved path, causing the Node.js runtime to execute the attacker's module code.
8. The attacker-controlled script performs malicious actions, such as reading environment variables or exfiltrating data, resulting in RCE.

## Impact

Successful exploitation results in full Remote Code Execution with the privileges of the MCP server process. This impacts confidentiality, integrity, and availability. Victims include developers using the server as an AI coding assistant and environments where AI agents connect to this MCP server, enabling potential exploitation via indirect prompt injection from malicious documentation or web content.

## Recommendation

1. Upgrade `functype-mcp-server` to a patched version that validates the `version` argument against an allowlist (e.g., regex for semver or dist-tags) and rejects alias syntaxes like `file:`, `npm:`, or URL paths.
2. Modify the `pnpm add` execution logic to include the `--ignore-scripts` flag to mitigate potential execution of arbitrary pre/post-install scripts, though this does not fix the dynamic import sink.
3. Restrict access to the MCP server by implementing authentication or by running the server in an isolated, non-privileged container with minimal access to the host filesystem.
