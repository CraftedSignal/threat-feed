---
title: Velocity.js Remote Code Execution via Function Constructor Bypass
slug: 2026-07-velocityjs-rce-bypass
description: Velocity.js versions up to 2.1.6 are vulnerable to Remote Code Execution (RCE) through an incomplete fix for a previous prototype pollution vulnerability, enabling attackers to craft malicious Velocity templates to leverage unfiltered property-read expressions and execute arbitrary JavaScript code on the server, leading to full server compromise.
date: "2026-07-24T16:31:34Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - velocityjs
  - rce
  - nodejs
  - vulnerability
  - server-side
vendors:
  - shepherdwind
products:
  - velocityjs <= 2.1.6
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The exploit chain passes a string containing JavaScript code ('return process.mainModule.require('child_process').execSync('whoami').toString()') to the Function constructor, which then executes this code within the Node.js environment.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The JavaScript payload specifically uses `child_process.execSync('whoami')`, which results in the execution of the `whoami` command via the system's command shell (e.g., cmd.exe on Windows).
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-7gfh-x38p-prh3
  - https://www.npmjs.com/package/velocityjs/v/2.1.7
  - https://github.com/shepherdwind/velocity.js/pull/192
  - https://github.com/shepherdwind/velocity.js/releases/tag/v2.1.7
iocs:
  - type: other
    value: process.mainModule.require('child_process').execSync('whoami')
ioc_counts:
  other: 1
rules:
  - title: Detect Velocity.js RCE via child_process.execSync
    description: Detects the execution of child_process.execSync via a Node.js application, which can be indicative of Remote Code Execution stemming from the Velocity.js vulnerability (GHSA-7gfh-x38p-prh3).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.003
      - T1059.007
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

A critical Remote Code Execution (RCE) vulnerability (GHSA-7gfh-x38p-prh3) has been identified in `velocityjs` versions up to 2.1.6, impacting applications that render attacker-controlled Velocity templates. This flaw represents a bypass of the previously issued fix for GHSA-j658-c2gf-x6pq, which addressed prototype pollution but incompletely mitigated the underlying issue. The vulnerability allows an attacker to manipulate unfiltered property-read expressions to invoke the JavaScript `Function` constructor with arbitrary code. This can lead to the execution of arbitrary shell commands on the server, enabling full system compromise, data exfiltration, and lateral movement. This exploit is particularly dangerous because it stems from a fix that was incomplete, leaving a critical attack vector open.

## Attack Chain

1. An attacker crafts and submits a malicious Velocity template containing an RCE payload to a vulnerable application.
2. The vulnerable `velocityjs` template engine begins processing the malicious template, specifically evaluating the expression `$x.constructor.constructor(...)`.
3. During template evaluation, the `getAttributes()` function in `references.cjs` is called for `$x.constructor`, which, due to a lack of filtering, resolves to the `Object` constructor.
4. Subsequently, the second `.constructor` lookup on the `Object` constructor is processed, also via `getAttributes()`, resolving to the JavaScript `Function` constructor.
5. The attacker's arbitrary JavaScript string payload, such as `"return process.mainModule.require('child_process').execSync('whoami').toString()"` from the PoC, is passed as an argument to the `Function` constructor.
6. This action dynamically creates a new JavaScript function object containing the attacker's supplied code, which includes a call to `child_process.execSync` for command execution.
7. The newly created malicious function is then assigned to a Velocity template variable (e.g., `$f`) using the `#set` directive.
8. The Velocity template subsequently invokes this variable (`$f()`), triggering the execution of the embedded system command (`whoami` in the PoC) on the underlying operating system and allowing the attacker to receive its output.

## Impact

Applications using `velocityjs` versions <= 2.1.6 are at severe risk of full server compromise. A successful exploitation allows an attacker to execute arbitrary shell commands with the privileges of the vulnerable application, potentially leading to the theft of sensitive data, access to cloud credentials, and the ability to pivot to other systems within the internal network. The vulnerability's nature as an RCE means direct control over the host system, making it a critical threat to any organization deploying affected `velocityjs` applications. The previous fix for prototype pollution (GHSA-j658-c2gf-x6pq) was bypassed, making this a more severe RCE rather than just data manipulation.

## Recommendation

* Upgrade all instances of `velocityjs` to version 2.1.7 or later immediately to apply the patch mentioned in the references.
* Deploy the provided Sigma rule to detect suspicious process creation patterns indicative of RCE attempts originating from Node.js applications.
* Enable comprehensive `process_creation` logging for all Node.js application servers to capture details such as parent process, image path, and command line arguments.
* Block the malicious Velocity template syntax identified in the IOCs at application input layers if immediate patching is not feasible.
