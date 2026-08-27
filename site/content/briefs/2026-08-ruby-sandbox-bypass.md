---
title: Sandbox Escape in execute_ruby Tool
slug: 2026-08-ruby-sandbox-bypass
description: The execute_ruby tool fails to sanitize the pseudo-terminal library, allowing attackers to escape the Ruby sandbox and execute arbitrary system commands via spawn entry points.
date: "2026-08-27T19:10:25Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - execute_ruby (1.4.0 to 1.6.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: Ruby'
    evidence: The pseudo-terminal library's spawn entry points are neither in the denylist nor replaced, so a normal tool call could reach them and start a shell, executing commands as the account running the server.
    confidence_band: high
cves:
  - id: CVE-2026-81097
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81097
---

The execute_ruby tool, designed as a read-only Ruby sandbox, contains a critical security vulnerability (CVE-2026-81097) in versions 1.4.0 through 1.6.0. The sandbox relies on a pattern-based denylist and method overriding for Kernel process-spawning functions to maintain isolation. However, the pseudo-terminal library's spawn entry points were entirely omitted from these security controls. An attacker capable of triggering a tool call can reach these unprotected entry points to spawn a shell, effectively bypassing the read-only constraints and executing arbitrary commands with the privileges of the server process. This flaw represents a significant risk for any application providing user-controlled Ruby execution environments. The vulnerability is addressed in version 1.6.1, which limits allowed requires to a data-only list and blocks dynamic dispatch to execution methods, while version 2.0.0 removes the tool entirely.

## Impact

Successful exploitation allows for full command execution on the host server. This bypasses the intended read-only sandbox restrictions, potentially leading to unauthorized data access, persistence, or lateral movement within the environment where the server process resides.

## Recommendation

- Upgrade the execute_ruby tool to version 1.6.1 or later immediately.
- If upgrading is not immediately feasible, remove the execute_ruby tool entirely (version 2.0.0 removal).
- Review application logs for unauthorized execution of PTY-related Ruby modules that fall outside the intended business logic scope.
