---
title: CVE-2026-93605 Sandbox Escape in vm2 NodeVM
slug: 2026-09-vm2-sandbox-escape
description: CVE-2026-93605 is a sandbox escape vulnerability in the vm2 library that allows attackers to execute arbitrary system commands via the improperly restricted child_process module.
date: "2026-09-18T16:06:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:vm2_project:vm2:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - rce
  - nodejs
products:
  - NodeVM (< 3.12.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can require child_process and execute arbitrary commands on the host system when NodeVM is configured with builtin:['*'] or explicit child_process allowance.
    confidence_band: high
cves:
  - id: CVE-2026-93605
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93605
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade vm2 to 3.12.1 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-93605 remediation guidance
  mitigation_plan:
    - priority: immediate
      action: Remove child_process from NodeVM built-in allowlist configurations
      owner: Application Security
      addresses: CVE-2026-93605
      evidence: Source describes child_process exclusion failure in denylist
---

CVE-2026-93605 describes a critical sandbox escape vulnerability affecting versions of the vm2 library prior to 3.12.1. The flaw exists within the NodeVM component, which is designed to provide an isolated execution environment for untrusted JavaScript code. Analysis reveals that the DANGEROUS_BUILTINS denylist, intended to restrict access to sensitive host-level functionality, fails to exclude the child_process module. 

When NodeVM is initialized with a configuration that allows built-in modules - specifically via the builtin:['*'] setting or explicit child_process inclusion - the sandbox fails to enforce boundaries. An attacker capable of injecting or controlling the code executed within the NodeVM instance can invoke child_process to interact with the underlying host operating system. This vulnerability enables arbitrary command execution with the privileges of the Node.js process, potentially leading to full system compromise depending on the container or host permissions. Organizations using vm2 to execute untrusted user input must upgrade to version 3.12.1 or later to ensure the denylist is correctly enforced.

## Impact

Successful exploitation of this vulnerability results in arbitrary remote code execution (RCE) on the host machine hosting the Node.js application. This poses a critical risk to any environment relying on vm2 for server-side code sandboxing, potentially allowing attackers to exfiltrate sensitive files, pivot within the network, or deploy persistent malware.

## Recommendation

* Upgrade the vm2 library to version 3.12.1 or higher immediately to apply the patch for CVE-2026-93605.
* Audit applications utilizing vm2 to determine if NodeVM is configured with built-in modules enabled.
* Implement defense-in-depth measures by running sandboxed Node.js processes in containers with restricted syscalls and minimal filesystem access to limit the impact of potential escapes.
* Transition away from vm2 if possible, as the library has historically faced multiple sandbox escape vulnerabilities.
