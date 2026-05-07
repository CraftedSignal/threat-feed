---
title: vm2 Sandbox Escape via Host Object Access
slug: 2026-05-vm2-sandbox-escape
description: A critical sandbox escape vulnerability exists in vm2 versions 3.10.5 and earlier, allowing attackers to bypass sandbox restrictions and execute arbitrary code on the host system by manipulating the host Object.
date: "2026-05-07T04:00:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sandbox-escape
  - rce
  - javascript
  - vm2
vendors:
  - npm
products:
  - vm2 (<= 3.10.5)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1611
    technique_name: Escape to Host
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1611
    technique_name: Escape to Host
references:
  - https://github.com/advisories/GHSA-47x8-96vw-5wg6
rules:
  - title: Detect vm2 Sandbox Escape via child_process
    description: Detects the execution of child_process.execSync within the vm2 sandbox, indicative of a sandbox escape attempt.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
    techniques:
      - T1611
    data_sources:
      - process_creation
      - windows
  - title: Detect WebAssembly Compilation with Suspicious Object
    description: Detects WebAssembly compilation events that include a suspicious object containing the Symbol(nodejs.util.inspect.custom) property, potentially indicating a sandbox escape attempt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1611
    data_sources:
      - process_creation
      - windows
  - title: Detect vm2 Sandbox Escape via HostObject.getOwnPropertySymbols
    description: Detects the use of HostObject.getOwnPropertySymbols which could lead to a sandbox escape in vm2.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1611
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

The vm2 library, a JavaScript sandbox environment, is vulnerable to a sandbox escape that can lead to remote code execution (RCE) on the host machine. This vulnerability, tracked as CVE-2026-43997, allows a malicious actor to gain access to the host's `Object` and bypass the intended security restrictions of the vm2 sandbox. While a previous attempt to mitigate this issue was implemented in commit ebcfe94ad2f864f0bc35e78cff1d921107cfd160, the fix was incomplete, leaving the sandbox vulnerable. Attackers can leverage this vulnerability to execute arbitrary code, potentially leading to complete system compromise. This issue affects vm2 versions 3.10.5 and earlier.

## Attack Chain

1.  The attacker gains initial access to the vm2 sandbox, likely through a web application or other service that utilizes the library.
2.  The attacker executes JavaScript code within the sandbox to obtain the host `Object` using techniques such as `__lookupGetter__`.
3.  The attacker calls `Buffer.apply` to get the `__proto__` of the Buffer object.
4.  The attacker retrieves the constructor of the `Object`.
5.  The attacker uses `HObject.getOwnPropertySymbols(Buffer.prototype)` to obtain the `Symbol(nodejs.util.inspect.custom)`.
6.  The attacker crafts a malicious object that overrides the `Symbol(nodejs.util.inspect.custom)` property.
7.  The attacker uses `WebAssembly.compileStreaming` to trigger the execution of the malicious code within the overridden `Symbol(nodejs.util.inspect.custom)` handler.
8.  This results in arbitrary code execution on the host machine outside of the intended sandbox environment.

## Impact

Successful exploitation of this vulnerability allows an attacker to escape the vm2 sandbox and execute arbitrary code on the host system. This can lead to a complete compromise of the host, including data theft, system modification, and denial of service. Given the widespread use of vm2 in various applications, a successful attack could have a significant impact.

## Recommendation

*   Upgrade to a patched version of vm2 that addresses CVE-2026-43997 to remediate the vulnerability.
*   Monitor process creation events for unexpected `child_process.execSync` calls originating from within the vm2 sandbox environment using the rule "Detect vm2 Sandbox Escape via child_process".
*   Implement strict input validation and sanitization to prevent the injection of malicious JavaScript code into the vm2 sandbox.
*   Enable auditing of WebAssembly compilation events to detect suspicious activity related to the `WebAssembly.compileStreaming` API, as shown in the rule "Detect WebAssembly Compilation with Suspicious Object".
