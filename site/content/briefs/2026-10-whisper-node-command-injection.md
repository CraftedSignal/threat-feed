---
title: OS Command Injection in Whisper-node
slug: 2026-10-whisper-node-command-injection
description: The whisper-node library through version 1.1.1 is vulnerable to OS command injection via unsanitized input in the whisper() function, allowing attackers to execute arbitrary shell commands.
date: "2026-10-14T16:33:38Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:whisper-node_project:whisper-node:*:*:*:*:*:node.js:*:*
tags:
  - command-injection
  - rce
  - nodejs
  - software-vulnerability
vendors:
  - Whisper-node
products:
  - whisper-node (<= 1.1.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The whisper-node library contains an OS command injection vulnerability that allows attackers to execute commands.
    confidence_band: high
cves:
  - id: CVE-2026-110640
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110640
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all applications using whisper-node <= 1.1.1 and implement temporary input sanitization or block public access to affected endpoints.
      owner: Application Security
      due: 24h
      evidence: Source document identifies this library as having an OS command injection vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade or replace the whisper-node dependency once a secure version is published by the project maintainers.
      owner: IT Operations
      addresses: CVE-2026-110640
      evidence: NVD states vulnerability exists in 1.1.1 and earlier.
---

Whisper-node versions through 1.1.1 are susceptible to an OS command injection vulnerability triggered by improper input validation within the whisper() function. The library uses the createCppCommand() utility to build command strings, which are subsequently passed to shelljs.exec() for execution. By supplying malicious shell metacharacters or command substitution sequences (such as $()) within the 'filePath' or 'whisperOptions.language' parameters, an attacker can manipulate the constructed command string. This vulnerability enables the execution of arbitrary commands with the same privileges as the underlying Node.js process, posing a critical risk to environments utilizing this library for server-side audio processing. 

## Attack Chain

1. The attacker identifies an application utilizing the vulnerable whisper-node library (<= 1.1.1) to process user-supplied file paths or language options.
2. The attacker crafts a malicious input string containing shell metacharacters (e.g., ;, &&, |) or command substitution syntax ($()).
3. The attacker submits the crafted input via an API endpoint or user interface that interfaces with the whisper() function.
4. The whisper() function passes the malicious input to the createCppCommand() internal helper.
5. The helper fails to sanitize the input and concatenates it into a shell command string.
6. The application invokes shelljs.exec() with the concatenated, malicious string.
7. The Node.js process executes the injected commands, resulting in unauthorized command execution.
8. The attacker achieves their objective, such as initial access, data exfiltration, or lateral movement.

## Impact

Successful exploitation of this vulnerability allows for remote code execution on the server hosting the Node.js application. Depending on the environment and the privileges of the Node.js process, an attacker could compromise sensitive data, gain persistence, or leverage the host machine to pivot into internal networks. The vulnerability is highly critical due to the ease of injection and the widespread use of such libraries in media-processing services.

## Recommendation

Prioritize the immediate update of the whisper-node dependency to a patched version (if available) or implement strict input validation for all values passed to the whisper() function. Ensure that no user-supplied data is passed directly into shell-executing functions.
