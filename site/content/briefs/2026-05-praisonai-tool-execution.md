---
title: PraisonAI Unsafe Tool Resolution Vulnerability
slug: 2026-05-praisonai-tool-execution
description: PraisonAI resolves tool names against module globals and `__main__` after failing to match declared tools, allowing an attacker who can influence tool-call names to invoke unintended application callables, leading to potential unauthorized state changes and command execution.
date: "2026-05-11T14:01:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:praison:praisonai:*:*:*:*:*:*:*:*
  - cpe:2.3:a:praison:praisonaiagents:*:*:*:*:*:python:*:*
tags:
  - vulnerability
  - code-execution
  - ai-agent
vendors:
  - PraisonAI
products:
  - PraisonAI (<= 4.6.36)
  - praisonaiagents (<= 1.6.36)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-44339
    cvss: 8.6
    epss: 0.00066
references:
  - https://github.com/advisories/GHSA-gmjg-hv98-qggq
  - CVE-2026-44339
rules:
  - title: Detect PraisonAI Undeclared Tool Execution via __main__
    description: Detects CVE-2026-44339 — Execution of undeclared functions within PraisonAI agents by identifying calls to the ToolExecutionMixin.execute_tool method with function names not present in the declared tool list.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect PraisonAI Tool Execution with Missing Permission Check
    description: Detects CVE-2026-44339 — Execution attempts where '_perm_allow' is None, indicating a missing permission check that could lead to the execution of undeclared tools.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

PraisonAI's `praisonaiagents` library exhibits an unsafe tool resolution vulnerability. Specifically, when resolving tool names, the system searches module globals and the `__main__` scope *after* failing to find a match in the declared tool list or the tool registry. Crucially, the default agent configuration sets `_perm_allow` to `None`, meaning that the permission gate does not enforce a strict allowlist of declared tools. This allows an attacker who can control or influence the tool-call names to invoke unintended application callables, bypassing the intended security boundary of declared tools. The vulnerability was verified on commit `d8a8a786915dc67a7c3021e24f72458f2eac5d9c` (v4.6.35).

## Attack Chain

1. The attacker identifies an application callable that is accessible via `__main__` or globals.
2. The attacker crafts a malicious input to the PraisonAI agent that specifies the name of the target callable as the "tool" to execute.
3. The `ToolExecutionMixin.execute_tool` function is called with the attacker-controlled tool name.
4. The agent first searches for the tool in its declared `self.tools` list. This search fails because the tool is undeclared.
5. The agent then attempts to retrieve the tool from the tool registry. This also fails.
6. The agent falls back to searching for the tool name in `globals()` and `__main__`. The attacker-specified callable is found in `__main__`.
7. The agent executes the callable directly, passing arguments as needed.
8. The attacker achieves arbitrary code execution within the context of the PraisonAI application, potentially leading to unauthorized state changes, data exposure, or command execution.

## Impact

Successful exploitation of this vulnerability can have significant consequences. In deployments where untrusted parties can influence tool-call names, attackers can execute undeclared application callables, bypassing intended security boundaries. Operators who rely on the declared tool list as a security control are vulnerable, as this control can be circumvented. If the application keeps privileged helper functions in process scope, the attacker can reuse those helpers with the application's own privileges, potentially leading to unauthorized state changes, data exposure, or command execution. Affected packages include `pip/praisonaiagents` (vulnerable: <= 1.6.36) and `pip/PraisonAI` (vulnerable: <= 4.6.36).

## Recommendation

*   Upgrade to a patched version of `praisonaiagents` and `PraisonAI` that addresses the unsafe tool resolution (CVE-2026-44339).
*   Configure the PraisonAI agent to use an explicit allowlist (`_perm_allow`) of permitted tools to prevent the execution of undeclared callables. Refer to the PraisonAI documentation for instructions on setting up the `_perm_allow` parameter.
*   Implement input validation and sanitization on tool-call names to prevent attackers from injecting arbitrary callable names.
*   Deploy the Sigma rule to detect attempts to execute undeclared functions through `ToolExecutionMixin`.
