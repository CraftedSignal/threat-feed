---
title: MCP-Shell Secure Mode Allowlist Bypass via Shell Interpreter
slug: 2026-08-mcp-shell-bypass
description: The mcp-shell tool contains a security bypass where improper validation of command-line arguments allows an attacker to execute arbitrary commands by leveraging a default-allowed shell interpreter.
date: "2026-08-25T16:02:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - mcp
  - container-security
products:
  - mcp-shell
affected_os:
  - Alpine Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The bypass allows an attacker to run arbitrary commands present in the container image (curl, wget, env, sed, grep, tar, etc.) under the identity of mcpuser.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-3x77-wg38-92r3
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Audit security.yaml files in mcp-shell deployments to ensure shell interpreters are excluded from the allowlist.
      owner: Security Engineering
      due: 24h
      evidence: 'Remediation section: Remove shell interpreters from the default security.yaml allowlist.'
  mitigation_plan:
    - priority: immediate
      action: Modify the allowlist configuration and implement argument validation in security.go.
      owner: IT Operations
      addresses: CWE-78
      evidence: 'Remediation section: Add argument-level validation in security.go to block shell command-mode flags.'
---

The mcp-shell utility, often deployed as an MCP (Model Context Protocol) tool, contains a critical security flaw in its secure mode validation logic. By default, the application ships with a `security.yaml` configuration that includes `/bin/bash` in its `allowed_executables` allowlist. The application's validation function, located in `security.go`, performs command authorization by splitting input strings on whitespace and evaluating only the first token (the executable) against the allowlist.

Because the validator fails to inspect subsequent arguments or identify shell command-mode flags, an attacker can supply a command payload such as `/bin/bash -c <arbitrary_command>`. The application validates the first token (`/bin/bash`), confirms it is on the allowlist, and proceeds to execute the full command string via `exec.CommandContext`. This results in the execution of unapproved binaries and shell scripts within the container environment under the `mcpuser` identity. The vulnerability is present in the official Docker image and requires no authentication or server configuration changes to exploit.

## Attack Chain

1. Attacker identifies an MCP tool interface exposing the `shell_exec` function.
2. Attacker prepares a JSON-RPC request to the `tools/call` method with `name` set to `shell_exec`.
3. Attacker sets the `command` argument to `/bin/bash -c <malicious_payload>` (e.g., `/bin/bash -c id`).
4. The application receives the input in `handler.go` and triggers the validation logic in `security.go`.
5. `security.go` splits the input string and identifies the executable as `/bin/bash`, which passes the allowlist check.
6. The `checkBlockedPatternsAndCommands` function fails to identify the `-c` flag as a security risk, returning a successful validation state.
7. The full command string is passed to `executor.go`, which invokes `exec.CommandContext` with the provided arguments.
8. The container executes the malicious payload via the shell interpreter, granting the attacker arbitrary command execution.

## Impact

Successful exploitation results in arbitrary OS command execution (CWE-78) within the container's environment. Attackers can leverage the installed base of binaries (e.g., `curl`, `wget`, `grep`, `sed`) to perform data exfiltration, read sensitive files accessible to `mcpuser`, modify the container's writable filesystem, or pivot to other network-accessible resources. The impact is elevated for production environments where these containers are used to bridge LLM agents with internal infrastructure.

## Recommendation

1. Remove shell interpreters (e.g., `/bin/bash`, `/bin/sh`, `/bin/dash`) from the `allowed_executables` list in `security.yaml` to prevent command-mode injection.
2. Implement argument-level validation in `security.go` to explicitly deny common shell command-mode flags (such as `-c`) when a shell interpreter is used.
3. Upgrade to a patched version of `mcp-shell` that incorporates regex-based argument validation for sensitive binaries.
4. Review and harden the container's entrypoint and environment variables to ensure that only the minimum necessary binaries are present in the runtime image.
