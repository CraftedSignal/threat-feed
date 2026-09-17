---
title: RestrictedPython Sandbox Escape via string.Formatter
slug: 2026-09-restrictedpython-sandbox-escape
description: RestrictedPython versions prior to 8.4 are vulnerable to a sandbox escape (CVE-2026-76825) via the string.Formatter module, which can bypass attribute guards to access sensitive objects and primitives.
date: "2026-09-17T19:14:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:restrictedpython:restrictedpython:*:*:*:*:*:*:*:*
tags:
  - sandbox-escape
  - cve-2026-76825
  - python
vendors:
  - RestrictedPython
products:
  - RestrictedPython (< 8.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Python'
    evidence: RestrictedPython could allow a sandbox escape when a policy exposes the standard library string module, or otherwise exposes string.Formatter, to restricted code.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This can bypass RestrictedPython's normal attribute guards and may allow access to sensitive objects such as function globals, builtins, file access, or code execution primitives.
    confidence_band: high
cves:
  - id: CVE-2026-76825
    cvss: 8.4
references:
  - https://github.com/advisories/GHSA-hp3v-5vw7-fx9w
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-76825
action_plan:
  priority: elevated
  owners:
    - Engineering
    - Security Operations
  immediate_actions:
    - action: Upgrade RestrictedPython to version 8.4 or later.
      owner: Engineering
      due: 48h
      evidence: The problem has been patched by blocking access to string.Formatter and unsafe string.Formatter traversal methods in safer_getattr.
  mitigation_plan:
    - priority: immediate
      action: Remove access to string.Formatter in custom restricted code policies.
      owner: Engineering
      addresses: CVE-2026-76825
      evidence: Do not expose the standard library string module or string.Formatter to restricted code.
---

RestrictedPython, a package designed to provide a sandbox environment for executing untrusted Python code, contains a vulnerability identified as CVE-2026-76825. This vulnerability allows for a sandbox escape if an application policy exposes the standard library 'string' module or the 'string.Formatter' class to the restricted environment. 

The issue stems from how 'string.Formatter' performs field resolution. Specifically, internal methods such as 'get_field' can perform attribute and item traversal that bypasses RestrictedPython's established attribute guards. By leveraging this behavior, an attacker capable of executing code within the restricted environment can obtain references to sensitive objects. These objects may include function globals, builtins, and code execution primitives, potentially enabling the attacker to break out of the sandbox to perform arbitrary operations on the underlying host system. This vulnerability affects all versions of RestrictedPython prior to 8.4.

## Impact

The vulnerability poses a severe risk to any application relying on RestrictedPython to safely execute untrusted user-supplied code. If successfully exploited, an attacker could escalate privileges from the restricted sandbox to the host environment, leading to full application compromise, unauthorized data access, or arbitrary code execution. The scope of impact is dependent on the application's configuration and the level of access granted to the 'string' module within its restricted environment.

## Recommendation

Prioritized actions for development and security teams:

- Upgrade the 'RestrictedPython' package to version 8.4 or later immediately to apply the fix in 'safer_getattr'.
- Review custom import policies to ensure the 'string' module and 'string.Formatter' class are not exposed to restricted execution environments.
- Audit custom global configurations passed to RestrictedPython to ensure neither 'string.Formatter' nor instances of it are accessible to untrusted code.
- Implement a policy of least privilege by restricting access to standard library modules within the Python sandbox environment.
