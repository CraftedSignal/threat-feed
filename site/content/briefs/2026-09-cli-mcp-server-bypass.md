---
title: Command Allowlist Bypass in cli-mcp-server
slug: 2026-09-cli-mcp-server-bypass
description: The cli-mcp-server package version 0.2.5 contains a vulnerability in the _validate_command_with_operators function allowing attackers to bypass command allowlists via shell substitution.
date: "2026-09-04T15:28:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - command-injection
  - execution
products:
  - cli-mcp-server (0.2.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can use shell command substitution syntax like $(...) or backticks to execute non-allowlisted commands that bypass the ALLOWED_COMMANDS validation check.
    confidence_band: high
cves:
  - id: CVE-2026-85660
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85660
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  mitigation_plan:
    - priority: immediate
      action: Disable ALLOW_SHELL_OPERATORS in cli-mcp-server configuration until a patched version is identified.
      owner: IT Operations
      addresses: CVE-2026-85660
      evidence: Source states the vulnerability occurs when ALLOW_SHELL_OPERATORS is enabled.
---

The cli-mcp-server package version 0.2.5 contains a vulnerability in the _validate_command_with_operators function that can be triggered when the ALLOW_SHELL_OPERATORS configuration is enabled. This flaw allows an attacker to bypass the defined ALLOWED_COMMANDS validation check by leveraging shell command substitution syntax, such as $(...) or backticks. When an attacker provides a crafted input string containing these shell metacharacters, the validation logic fails to correctly filter the command execution, leading to the execution of non-allowlisted and potentially malicious commands. This vulnerability highlights a failure in input sanitization within the server's command processing logic, posing a significant risk for systems that rely on this package to restrict command execution environments. Defenders should identify instances of cli-mcp-server and ensure they are updated to a non-vulnerable version, or disable the ALLOW_SHELL_OPERATORS feature if command execution flexibility is not required.

## Impact

Successful exploitation allows for the execution of arbitrary, non-allowlisted shell commands, potentially leading to unauthorized system access, data exfiltration, or further lateral movement depending on the privileges of the process hosting the cli-mcp-server.

## Recommendation

* Identify and audit all applications currently using cli-mcp-server version 0.2.5.
* Update cli-mcp-server to a version that patches the _validate_command_with_operators validation logic.
* If an update is not immediately feasible, set ALLOW_SHELL_OPERATORS to false to mitigate the specific bypass vector.
