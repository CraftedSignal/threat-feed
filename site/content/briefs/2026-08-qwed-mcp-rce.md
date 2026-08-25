---
title: Remote Code Execution in qwed-mcp via Unsafe SymPy Input
slug: 2026-08-qwed-mcp-rce
description: The qwed-mcp library v0.2.0 is vulnerable to arbitrary remote code execution because it passes unsanitized input to SymPy's parse_expr function, allowing attackers to execute arbitrary system commands via Python code injection.
date: "2026-08-25T16:01:38Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - python
  - injection
  - supply-chain
vendors:
  - QWED-AI
products:
  - qwed-mcp (0.2.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows an attacker to inject and execute arbitrary Python expressions, including __import__('os').system() to execute OS commands.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mw6r-2hvm-4rp2
rules:
  - title: Detect Python RCE via SymPy parse_expr Abuse
    description: Detects potential exploitation of unsafe parse_expr usage by monitoring for unexpected usage of os.system or other sensitive built-ins inside Python scripts, though this is best mitigated at the code level.
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
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch the verify_math_expression function in qwed-mcp using the provided AST validation logic.
      owner: IT Operations
      due: 24h
      evidence: Remediation section of the GHSA advisory.
  hunt_leads:
    - lead: Identify all services currently running the qwed-mcp library.
      technique_id: T1059.003
      data_needed:
        - Software inventory logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The library is publicly available and any usage with external input is vulnerable.
  mitigation_plan:
    - priority: immediate
      action: 'Restrict global_dict in all sympy parse_expr calls to {__builtins__: {}}.'
      owner: IT Operations
      addresses: CWE-94
      evidence: Remediation section of the GHSA advisory.
  gaps:
    - Lack of native runtime protection against Python evaluation vulnerabilities.
---

The qwed-mcp library, specifically version 0.2.0, contains a critical security vulnerability in the `verify_math_expression` function located in `src/qwed_mcp/engines/math_engine.py`. The function accepts raw string input for mathematical expressions and forwards them to `sympy.parsing.sympy_parser.parse_expr()` without proper sanitization or namespace restriction. 

Internally, SymPy's `parse_expr()` utilizes the Python `eval()` function. Because the library fails to restrict the global namespace or define an empty `__builtins__` dictionary, the evaluation process inherits the current module's full built-in scope. This allows an attacker to inject and execute arbitrary Python expressions, including `__import__('os').system()`. This vulnerability facilitates full remote code execution in the context of the running process with the privileges of the executing user, as confirmed by successful exploitation experiments in a standard Python Docker container.

## Attack Chain

1. An attacker identifies a service or application utilizing `qwed-mcp` that allows submission of arbitrary mathematical expressions to the `verify_math_expression` function.
2. The attacker crafts a malicious Python payload (e.g., `__import__('os').system('command')`) designed to escape the expected mathematical evaluation context.
3. The target application receives the payload and passes it as the `expression` or `claimed_result` argument to `qwed_mcp.engines.math_engine.verify_math_expression`.
4. `verify_math_expression` performs basic string replacement (`^` to `**`) and forwards the unsanitized string to `sympy.parsing.sympy_parser.parse_expr`.
5. `parse_expr` invokes Python's `eval()` function using the unrestricted module namespace, which includes access to `os` and other powerful modules via `__builtins__`.
6. The `os.system()` payload executes the specified OS commands with the permissions of the application process.
7. The attacker achieves persistent access or exfiltration by redirecting output to temporary files or establishing outbound C2 communication.

## Impact

Successful exploitation allows an attacker to achieve full remote code execution on the host machine or container running the `qwed-mcp` library. This grants the attacker the ability to read, modify, or delete files, exfiltrate sensitive environment variables and credentials, and pivot into the internal network. Because the vulnerability is directly accessible via the library's API, any application integrating `qwed-mcp` that exposes this function to external input is at immediate risk of total system compromise.

## Recommendation

* Immediately upgrade to a patched version of `qwed-mcp` if available, or apply the remediation patch provided in the advisory to `math_engine.py`.
* Update `math_engine.py` to implement strict AST pre-validation using the `ast` module to ensure only safe mathematical constructs are processed.
* Explicitly set `global_dict={"__builtins__": {}}` in all calls to `parse_expr()` to eliminate the possibility of accessing sensitive built-in functions during evaluation.
* Audit applications utilizing `qwed-mcp` to ensure no user-controlled input reaches the `verify_math_expression` function without secondary validation.
