---
title: PraisonAI Python Sandbox Escape via Code Injection
slug: 2024-01-praisonai-rce
description: PraisonAI's AST-based Python sandbox is vulnerable to code injection allowing arbitrary code execution when running untrusted agent code by bypassing attribute filtering using `type.__getattribute__` which could lead to complete system compromise.
date: "2024-01-17T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-injection
  - sandbox-escape
  - python
vendors:
  - PraisonAI
products:
  - PraisonAI
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-40158
    cvss: 8.6
references:
  - https://github.com/advisories/GHSA-3c4r-6p77-xwr7
rules:
  - title: Detect PraisonAI Sandbox Escape Attempt via type.__getattribute__
    description: Detects attempts to bypass PraisonAI's AST-based Python sandbox by using type.__getattribute__ to access restricted attributes like __subclasses__ or __globals__.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.006
    data_sources:
      - process_creation
      - linux
  - title: Detect PraisonAI Sandbox Escape Attempt via system call after attribute bypass
    description: Detects attempts to execute system commands after a potential sandbox escape, indicated by the use of type.__getattribute__ followed by a system call (e.g., curl, wget).
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.006
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

PraisonAI, a platform that executes untrusted agent code, contains a flaw in its AST-based Python sandbox. The sandbox attempts to restrict access to dangerous Python attributes like `__subclasses__` and `__globals__` by filtering `ast.Attribute` nodes. However, this filtering is incomplete, as it does not account for dynamic attribute resolution using built-in methods such as `type.__getattribute__`. An attacker can leverage this oversight to bypass the intended security restrictions and achieve arbitrary code execution. This vulnerability affects PraisonAI versions prior to 4.5.128 and was reported by Lakshmikanthan K (letchupkt). Successful exploitation allows attackers to escape the sandbox, enabling sensitive data access, arbitrary command execution, and potential system compromise.

## Attack Chain

1. The attacker injects malicious Python code into the PraisonAI agent execution environment.
2. The injected code uses `type.__getattribute__` to access the `__bases__` attribute of an integer class (`int_cls`). This bypasses the AST-based filter, which only checks `ast.Attribute` nodes.
3. The code retrieves the object class (`obj_cls`) from the `__bases__` attribute.
4. The attacker then uses `type.__getattribute__` again to access the `__subclasses__` attribute of the `obj_cls`. This further bypasses the filter.
5. The code iterates through all subclasses to find the `_wrap_close` class.
6. It then uses `type.__getattribute__` to get the `__init__` method of the `_wrap_close` class and subsequently accesses its `__globals__` attribute.
7. This provides access to the global namespace, allowing the attacker to retrieve the `system` function.
8. Finally, the attacker uses the `system` function to execute arbitrary commands, such as exfiltrating environment variables to an attacker-controlled server using `curl`.

## Impact

This vulnerability allows attackers to escape the intended Python sandbox and execute arbitrary code with the privileges of the host process. Attackers can access sensitive data such as environment variables, API keys, and local files. Arbitrary system commands can be executed, potentially leading to modification or deletion of files. In environments that execute untrusted code, this can lead to full system compromise, data exfiltration, and potential lateral movement within the infrastructure. This poses a significant risk to multi-tenant agent platforms, CI/CD pipelines, and shared systems.

## Recommendation

*   Upgrade PraisonAI to version 4.5.128 or later to patch CVE-2026-40158.
*   Deploy the Sigma rules in this brief to your SIEM to detect potential exploitation attempts.
*   Review and harden any custom code that executes untrusted Python, paying special attention to dynamic attribute access patterns.
