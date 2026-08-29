---
title: RestrictedPython Positional-Only Argument Guard Bypass
slug: 2026-08-restrictedpython-bypass
description: RestrictedPython (<= 8.2) fails to validate positional-only arguments, allowing an attacker to shadow security guard hooks (_getattr_, _getitem_, _write_, _print_) and bypass sandbox access policies.
date: "2026-08-29T03:13:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:restrictedpython:restrictedpython:*:*:*:*:*:*:*:*
vendors:
  - RestrictedPython
products:
  - RestrictedPython (<= 8.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Python'
    evidence: An attacker can define a function using these names as positional-only arguments to shadow the application-provided security policy.
    confidence_band: high
cves:
  - id: CVE-2026-55830
    cvss: 8.3
    epss: 0.00401
references:
  - https://github.com/advisories/GHSA-ffg3-p8fm-mjx2
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-55830
action_plan:
  priority: elevated
  owners:
    - Development
    - Security Operations
  immediate_actions:
    - action: Upgrade RestrictedPython to 8.3 or later
      owner: Development
      due: 72h
      evidence: 'Source states: The fix validates positional-only argument names the same way the other argument kinds are already validated.'
  mitigation_plan:
    - priority: immediate
      action: Implement a static code analysis regex to block function definitions containing positional-only arguments with leading underscores.
      owner: Development
      addresses: CVE-2026-55830
      evidence: 'Workaround: reject any submitted code whose function or lambda definitions use positional-only parameters with leading-underscore names.'
---

The RestrictedPython library utilizes specific guard hooks (such as `_getattr_`, `_getitem_`, `_write_`, and `_print_`) to rewrite and enforce security policies for sandboxed Python code. While the library correctly validates these protected names against standard function arguments, `*args`, `**kwargs`, and keyword-only arguments, it fails to perform the same checks for positional-only arguments defined before the `/` separator in a function signature.

This vulnerability allows an attacker to define a function with one of the restricted guard names as a positional-only argument. This effectively localizes the name, causing the Python interpreter to shadow the embedding application's intended security hook. When the sandboxed code executes, it invokes the attacker's defined function instead of the policy-enforcing hook. Depending on the broader application context, this bypass can be escalated into remote code execution, particularly if the application performs unsafe operations like unpickling objects controlled by the sandboxed environment.

## Impact

The vulnerability allows for complete bypass of sandboxed environment restrictions. In scenarios where the host application relies on RestrictedPython to safely execute user-provided code, attackers can access forbidden system attributes, modify protected data, or exfiltrate information. In applications that perform insecure operations on sandbox-controlled objects, such as serialization or deserialization, this primitive can lead to remote code execution (RCE). The impact is highly dependent on how the embedding application utilizes the library.

## Recommendation

Prioritized actions for development and security operations teams:
* Upgrade RestrictedPython to the version containing the security patch as soon as it is released (addressing CVE-2026-55830).
* If an immediate upgrade is not possible, implement a static analysis check in the ingestion pipeline to reject any Python source code that uses positional-only parameters containing leading underscores (e.g., `def f(_getattr_=..., /):`).
* Review application code that utilizes RestrictedPython to ensure that objects returned from or manipulated by the sandbox are handled using secure, non-executable serialization methods (e.g., avoiding pickle).
