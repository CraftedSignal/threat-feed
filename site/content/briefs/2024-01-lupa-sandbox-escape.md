---
title: Lupa Sandbox Escape via Incomplete attribute_filter Enforcement
slug: 2024-01-lupa-sandbox-escape
description: The lupa library's attribute_filter is not consistently applied when attributes are accessed through built-in functions like getattr and setattr, leading to a sandbox escape and arbitrary code execution.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - lupa
  - sandbox-escape
  - rce
  - python
vendors:
  - lupa
products:
  - lupa
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-69v7-xpr6-6gjm
rules:
  - title: Detect Suspicious Process Creation from Python
    description: Detects suspicious process creation events originating from the Python interpreter, which could indicate a sandbox escape.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect getattr Usage in Lua Code
    description: Detects the usage of getattr in Lua code, which could be a sign of vulnerability exploitation. This rule looks for Lua code that calls python.builtins.getattr in process creation events.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The lupa library, version 2.6 and earlier, contains a vulnerability in its `attribute_filter` implementation. This filter aims to restrict access to sensitive Python attributes when exposing objects to Lua code. However, the filter is inconsistently applied, specifically when attributes are accessed through built-in functions like `getattr` and `setattr`. This inconsistency allows an attacker with the ability to execute Lua code to bypass the intended restrictions, ultimately leading to arbitrary code execution on the host system. This vulnerability impacts applications that rely on `attribute_filter` as a security control for untrusted Lua code execution, particularly if they allow access to Python builtins.

## Attack Chain

1. The attacker gains the ability to execute arbitrary Lua code within an application that uses the lupa library.
2. The Lua code gains access to a Python object exposed through lupa.
3. The Lua code utilizes the `python.builtins.getattr` function to access the `__class__` attribute of the exposed Python object, bypassing the `attribute_filter`.
4. The Lua code uses `getattr` again to access the `__mro__` attribute of the class, walking up the inheritance chain.
5. The Lua code calls the `__subclasses__()` method (accessed via `getattr`) to enumerate all subclasses of the base object class.
6. The Lua code iterates through the subclasses, searching for a class containing `os._wrap_close`.
7. The Lua code uses `getattr` to access the `__init__` attribute of the identified subclass, and then accesses its `__globals__` attribute to retrieve the `os.system` function.
8. Finally, the Lua code uses `setattr` to assign the `os.system` function to an attribute of the original Python object and executes arbitrary commands on the host system, achieving sandbox escape.

## Impact

Successful exploitation of this vulnerability allows an attacker to bypass the `attribute_filter` in the lupa library. This leads to arbitrary code execution within the host Python process. The impact is a full sandbox escape, potentially allowing the attacker to compromise the entire system. Any application using lupa to execute untrusted Lua code is vulnerable if it relies solely on `attribute_filter` and doesn't disable access to Python builtins. This affects applications using lupa version 2.6 or earlier.

## Recommendation

*   Upgrade to a patched version of the `lupa` library that addresses this vulnerability.
*   If upgrading is not immediately feasible, disable access to Python builtins via the `register_builtins=False` option when creating a `LuaRuntime` instance.
*   Monitor process creation events for suspicious processes spawned by the Python interpreter, as a sign of successful exploitation (see Sigma rule `Detect Suspicious Process Creation from Python`).
*   Implement additional security controls, such as seccomp profiles, to limit the capabilities of the Python process.
