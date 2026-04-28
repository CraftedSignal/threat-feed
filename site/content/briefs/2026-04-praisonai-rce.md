---
title: PraisonAI Agent Subprocess Sandbox Escape via Frame Traversal
slug: 2026-04-praisonai-rce
description: A critical vulnerability (CVE-2026-39888) in PraisonAI agents through version 1.5.113 allows remote code execution via a sandbox escape in the `execute_code` function due to insufficient attribute blocking, enabling privilege escalation, credential access, and lateral movement.
date: "2026-04-08T19:17:28Z"
severities:
  - critical
tags:
  - sandbox-escape
  - remote-code-execution
  - python
  - praisonai
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-qf73-2hrx-xprp
rules:
  - title: Detect PraisonAI Agent Sandbox Escape Attempt via Frame Traversal
    description: Detects attempts to exploit the PraisonAI agent sandbox escape vulnerability by identifying code that accesses frame attributes within the sandboxed environment.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
  - title: Detect PraisonAI Agent Subprocess Execution
    description: Detects execution of the praisonaiagents python_tools subprocess, which may indicate exploitation activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability exists in PraisonAI agents, specifically affecting the `execute_code` function within the `praisonaiagents.tools.python_tools` module. This flaw allows an attacker to escape the intended subprocess sandbox environment due to an incomplete blocklist of attributes.  The vulnerability stems from the `sandbox_mode="sandbox"` default configuration, intended to restrict user-supplied code execution. The AST-based blocklist designed to prevent access to dangerous attributes is weaker in the subprocess execution path compared to the direct execution path.  This discrepancy allows attackers to leverage frame traversal techniques to access the real Python builtins and execute arbitrary code.  This vulnerability affects all versions of `praisonaiagents` shipping with the default `sandbox_mode="sandbox"` configuration through version 1.5.113. The vulnerability was tested and confirmed on PraisonAI Agents version 1.5.113 running on Python 3.10.

## Attack Chain

1. An attacker submits malicious Python code via the `execute_code` API.
2. The `_execute_code_sandboxed()` function is invoked to execute the code within a subprocess.
3. The subprocess executes the attacker-supplied code within a restricted environment defined by `safe_globals`.
4. The attacker's code triggers a `ZeroDivisionError` exception to gain access to the traceback object.
5. Using the `__traceback__`, `tb_frame`, `f_back`, and `f_builtins` attributes (which are not properly blocked), the attacker traverses the stack frames to reach the parent frame's `builtins`.
6. The attacker retrieves the `exec` function from the parent frame's `builtins`.
7. The attacker uses the retrieved `exec` function to execute arbitrary code, bypassing the intended restrictions.
8. This leads to arbitrary command execution on the host system.

## Impact

Successful exploitation allows attackers to execute arbitrary commands on the host system within the context of the subprocess user.  This can lead to several severe consequences: arbitrary file system read and write access, potentially exposing sensitive source code, credentials, and configuration files; exfiltration of environment variables, including API keys and other secrets; unrestricted outbound network connections, enabling communication with attacker-controlled infrastructure; and lateral movement within the compromised network. This vulnerability impacts all standard PraisonAI agent deployments and exposes all agent users, which can lead to full system compromise with a single API call.

## Recommendation

*   Apply the suggested fix by merging `blocked_attrs` into a single shared constant to ensure the subprocess wrapper uses the same attribute blocklist as the direct mode, as described in the **Suggested Fix** section.
*   Implement an AST rule to block any `ast.Attribute` node whose `attr` starts with `_`, effectively preventing access to private attributes at the AST level, as described in the **Suggested Fix** section.
*   Add the text-pattern blocklist (`dangerous_patterns`) check from `_execute_code_direct` to `_execute_code_sandboxed` as an additional layer of defense, as described in the **Suggested Fix** section.
*   Monitor web server logs for unusual requests targeting the `execute_code` API, looking for indicators of exploit attempts. Use the information in the **Proof of Concept** section to identify potential payloads.
