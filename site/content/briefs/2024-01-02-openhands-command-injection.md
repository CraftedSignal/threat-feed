---
title: OpenHands Command Injection Vulnerability in Git Diff Handler
slug: 2024-01-02-openhands-command-injection
description: A command injection vulnerability exists in OpenHands' `get_git_diff()` method, allowing authenticated attackers to execute arbitrary commands in the agent sandbox via the `/api/conversations/{conversation_id}/git/diff` endpoint by exploiting the unsanitized `path` parameter.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - web-application
  - openhands
vendors:
  - OpenHands
products:
  - OpenHands
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-7h8w-hj9j-8rjw
rules:
  - title: Detect OpenHands Git Diff Command Injection Attempt
    description: Detects command injection attempts in the OpenHands Git Diff endpoint by identifying shell metacharacters in the path parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect OpenHands Git Diff Suspicious File Path Access
    description: Detects attempts to access sensitive files via the OpenHands Git Diff endpoint, indicating potential command injection exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenHands is vulnerable to command injection due to insufficient sanitization of the `path` parameter in the `/api/conversations/{conversation_id}/git/diff` API endpoint. This endpoint, handled by the `get_git_diff()` method within `openhands/runtime/utils/git_handler.py`, allows authenticated users to pass arbitrary commands to the underlying shell.  The vulnerability exists because the `file_path` parameter is directly interpolated into a shell command string using Python's `.format()` method without sanitization, allowing for the interpretation of shell metacharacters. This bypasses the normal agent command execution channels and provides a direct path for attackers to execute code within the agent sandbox.  The affected versions are pip/openhands < 1.5.0. This vulnerability was reported on 2026-03-25.

## Attack Chain

1. An authenticated user sends a crafted HTTP GET request to the `/api/conversations/{conversation_id}/git/diff` endpoint.
2. The request includes a malicious `path` parameter containing shell metacharacters (e.g., `;`, `|`, `&`).
3. The `git_diff` function in `openhands/server/routes/files.py` receives the `path` parameter.
4. The `path` parameter is passed unsanitized to the `runtime.get_git_diff` function.
5. The `get_git_diff` function in `openhands/runtime/base.py` then calls `self.git_handler.get_git_diff(file_path)`.
6. Within `openhands/runtime/utils/git_handler.py`, the `file_path` is directly inserted into the `GIT_DIFF_CMD` string using `.format()` without sanitization.
7. The resulting command string is executed via `subprocess.run` with `shell=True` in `openhands/runtime/utils/git_diff.py`, enabling shell metacharacter interpretation.
8. The attacker-supplied commands are executed on the system, achieving arbitrary code execution.

## Impact

Successful exploitation allows attackers to execute arbitrary commands on the runtime container as root, leading to significant compromise.  Attackers can read sensitive files (e.g., `.env`, API keys, source code), write arbitrary files, inject malicious code, establish reverse shells for persistent access, and potentially escape the container if Docker is misconfigured. This impacts all OpenHands deployments exposing the vulnerable endpoint.

## Recommendation

*   Upgrade OpenHands to the latest version that includes the fix from PR #13051 to address the command injection vulnerability.
*   Deploy the Sigma rule `Detect OpenHands Git Diff Command Injection Attempt` to your SIEM to detect exploitation attempts based on shell metacharacters in the `path` parameter.
*   Implement input validation and sanitization for the `path` parameter in the `/api/conversations/{conversation_id}/git/diff` endpoint to prevent shell metacharacters from being processed.
