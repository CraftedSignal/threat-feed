---
title: 'vm2 CVE-2023-37903 Patch Bypass: Remote Code Execution'
slug: 2026-05-vm2-rce-bypass
description: 'The vm2 npm package has a remote code execution vulnerability due to a patch bypass for CVE-2023-37903; the vulnerability occurs because the check for `nesting: true` and `require: false` in `nodevm.js` uses strict equality, which can be bypassed by omitting the `require` option entirely, allowing an attacker to execute arbitrary OS commands.'
date: "2026-05-29T17:52:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:vm2_project:vm2:*:*:*:*:*:node.js:*:*
tags:
  - vm2
  - rce
  - sandbox-escape
  - CVE-2026-47137
vendors:
  - npm
products:
  - vm2 (<= 3.11.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2023-37903
    cvss: 9.8
    epss: 0.36362
references:
  - https://github.com/advisories/GHSA-m4wx-m65x-ghrr
rules:
  - title: Detect CVE-2026-47137 Exploitation Attempt — vm2 sandbox escape via child_process
    description: Detects CVE-2026-47137 exploitation attempt — attempts to require child_process within a vm2 sandbox with nesting enabled, indicating a potential sandbox escape.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect CVE-2026-47137 Exploitation Attempt — vm2 requiring vm2
    description: Detects CVE-2026-47137 exploitation attempt — requiring 'vm2' from within a vm2 sandbox
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The vm2 npm package, a sandboxing solution for Node.js, is vulnerable to a remote code execution (RCE) bypass of the CVE-2023-37903 patch. This bypass occurs because the check implemented to prevent the combination of `nesting: true` and `require: false` uses strict equality (`===`). By simply omitting the `require` option when instantiating a `NodeVM`, the check is bypassed, as `options.require` becomes `undefined`, not `false`. This oversight allows an attacker to bypass the intended security restrictions and execute arbitrary code on the host system. This vulnerability affects vm2 versions 3.11.3 and earlier and poses a significant risk to applications relying on vm2 for sandboxing untrusted code.

## Attack Chain

1. An attacker injects malicious JavaScript code into a `NodeVM` instance configured with `nesting: true` but without explicitly setting the `require` option.
2. The initial security check in `nodevm.js` at line 263 fails because `options.require` is `undefined` instead of `false`, thus bypassing the intended restriction.
3. The code inside the `NodeVM` then uses `require('vm2')` to gain access to the vm2 library itself.
4. The injected code constructs a new, nested `NodeVM` instance, this time explicitly enabling the `child_process` module via `require: { builtin: ['child_process'] }`.
5. The nested `NodeVM` instance is then used to execute arbitrary operating system commands using `child_process.execSync()`.
6. The output of the command is converted to a string.
7. The string is returned as the result of the initial `nvm.run()` call, demonstrating successful command execution on the host.
8. The attacker achieves full remote code execution on the host system.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the host system. In a multi-tenant environment or any situation where vm2 is used to sandbox untrusted code, this can lead to complete system compromise. The attacker can gain access to sensitive data, install malware, or pivot to other systems on the network. The observed damage is full RCE.

## Recommendation

- Upgrade to a patched version of vm2 that addresses this vulnerability.
- Apply the suggested fix to `nodevm.js` locally if an immediate upgrade is not possible: Change the check to `if (options.nesting === true && !options.require)` as documented in the advisory.
- Deploy the Sigma rules provided to detect attempts to exploit this vulnerability, focusing on `process_creation` events originating from within vm2 sandboxes.
- Monitor for unusual `require()` calls within vm2 sandboxes, especially those attempting to load the `child_process` module.
