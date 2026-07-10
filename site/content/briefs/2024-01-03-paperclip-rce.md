---
title: Paperclip AI OS Command Injection via Execution Workspace cleanupCommand
slug: 2024-01-03-paperclip-rce
description: A critical OS command injection vulnerability exists in Paperclip AI v2026.403.0 within the execution workspace lifecycle. By injecting arbitrary shell commands into the `cleanupCommand` field via the `PATCH /api/execution-workspaces/:id` endpoint, an attacker can execute these commands on the server when the workspace is archived.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - rce
  - paperclip
  - vulnerability
vendors:
  - Paperclip
products:
  - Paperclip AI
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-vr7g-88fq-vhq3
  - https://github.com/user-attachments/files/26697937/poc_paperclip_rce.py
rules:
  - title: Detect Paperclip Cleanup Command Injection
    description: Detects potential OS command injection attempts in Paperclip AI by monitoring PATCH requests to the /api/execution-workspaces/:id endpoint with suspicious cleanupCommand values.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Paperclip Workspace Archive Triggering RCE
    description: Detects suspicious workspace archival requests that may trigger remote code execution due to a command injection vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Paperclip AI v2026.403.0 is vulnerable to OS command injection. The vulnerability resides in the execution workspace lifecycle, specifically within the `workspace-runtime.ts` component. By sending a crafted `PATCH` request to the `/api/execution-workspaces/:id` endpoint, an attacker can inject arbitrary shell commands into the `cleanupCommand` field. When the affected workspace is archived the server executes the injected command via `child_process.spawn(shell, ["-c", cleanupCommand])`. This vulnerability is exploitable in all deployment modes, including `local_trusted` (zero authentication) and `authenticated` (any company user). Successful exploitation allows for remote code execution with the privileges of the Paperclip server process on Linux, macOS, and Windows platforms. Proof of concept demonstrations include arbitrary file write, system information exfiltration, and GUI application launch.

## Attack Chain

1. The attacker sends a `GET` request to `/api/companies` to obtain a company ID.
2. The attacker sends a `GET` request to `/api/companies/{company_id}/execution-workspaces` to enumerate execution workspaces and retrieve a workspace ID.
3. If the workspace is not in an `active` state, the attacker sends a `PATCH` request to `/api/execution-workspaces/{workspace_id}` with the body `{"status": "active"}` to reactivate it.
4. The attacker crafts a `PATCH` request to `/api/execution-workspaces/{workspace_id}` with a JSON body containing a malicious `cleanupCommand` within the `config` object, such as `{"config": {"cleanupCommand": "echo RCE_PROOF > \\"/tmp/rce-proof.txt\\""}}`.
5. The server stores the injected `cleanupCommand` in the workspace configuration.
6. The attacker triggers the command injection by sending a `PATCH` request to `/api/execution-workspaces/{workspace_id}` to archive the workspace, setting `"status": "archived"`.
7. The server executes the injected command using `child_process.spawn(shell, ["-c", cleanupCommand])`.
8. The attacker achieves remote code execution on the server, potentially leading to data exfiltration, lateral movement, or other malicious activities.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the Paperclip server with the privileges of the server process. This can lead to a range of severe impacts, including remote code execution, data exfiltration of sensitive information (e.g., system info, environment variables, source code), lateral movement within the network, and potential supply chain attacks by injecting backdoors into managed repositories. In `local_trusted` mode, this requires zero authentication, making it easily exploitable by malicious local processes or web pages.

## Recommendation

*   Apply input validation to the `cleanupCommand` and `teardownCommand` fields in the PATCH handler to prevent the injection of malicious commands.
*   Implement command allowlisting, permitting only a predefined set of safe commands for workspace cleanup.
*   Replace `spawn(shell, ["-c", command])` with `execFile()` using an argument array to mitigate shell metacharacter injection.
*   Implement proper authorization checks BEFORE processing the PATCH request to validate user permissions.
*   Deploy the Sigma rule `DetectPaperclipCleanupCommandInjection` to identify attempts to exploit this vulnerability via the PATCH request to `/api/execution-workspaces/:id`.
*   Run cleanup commands in a sandboxed environment to minimize the impact of potential exploits.
