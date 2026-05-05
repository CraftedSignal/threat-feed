---
title: VM2 Sandbox Breakout via Inspect Function Allows Remote Code Execution
slug: 2026-05-vm2-sandbox-breakout
description: A sandbox breakout vulnerability exists in VM2 through the `inspect` function, allowing attackers to escape the sandbox and execute arbitrary commands on the host system.
date: "2026-05-06T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sandbox-escape
  - rce
  - vm2
vendors:
  - npm
products:
  - vm2 (<= 3.10.3)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Execution
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-24781
    cvss: 9.8
references:
  - https://github.com/advisories/GHSA-v37h-5mfm-c47c
rules:
  - title: Detect VM2 Sandbox Breakout - Child Process Execution
    description: Detects execution of child processes from within a VM2 context, indicating a potential sandbox escape.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect VM2 Sandbox Breakout - File Creation
    description: Detects file creation events originating from a Node.js process that may indicate a sandbox escape attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A critical sandbox escape vulnerability has been identified in VM2, a popular JavaScript sandbox environment for Node.js. This vulnerability, assigned CVE-2026-24781, stems from the improper handling of proxies within the `inspect` function. By exploiting this flaw, an attacker can bypass the VM2 sandbox and execute arbitrary code on the host system. The vulnerability affects VM2 versions 3.10.3 and earlier. This allows for remote code execution under the assumption that arbitrary code can be executed inside the context of a VM2 sandbox. Defenders should update to the latest version and implement the provided detections.

## Attack Chain

1. The attacker executes code within the VM2 sandbox, leveraging the `inspect` function to log details of objects.
2. The `inspect` method unwraps proxies to access object details.
3. The attacker uses `this.seen` of the `stylize` function to extract unwrapped values, gaining access to the internal proxy handler of VM2.
4. The attacker accesses the sandbox object within the proxy handler. Accessing the handler is wrapped by a VM2 proxy.
5. The wrapped sandbox object is given into the sandbox.
6. The attacker writes a wrapped host object to the wrapped sandbox object.
7. The attacker reads the raw host object from the raw sandbox object, bypassing the proxy bridge.
8. The attacker utilizes the `child_process` module to execute arbitrary commands on the host system, such as creating a file named `pwned`.

## Impact

Successful exploitation of this vulnerability allows attackers to perform Remote Code Execution (RCE) on the host system where the VM2 sandbox is running. This can lead to complete system compromise, data exfiltration, or denial of service. Given VM2's usage in various applications for untrusted code execution, the impact could be widespread.

## Recommendation

*   Upgrade to the latest version of `vm2` to patch CVE-2026-24781.
*   Deploy the Sigma rules provided below to detect potential exploitation attempts.
*   Monitor process creation events for suspicious commands executed by Node.js processes as highlighted in the attack chain.
