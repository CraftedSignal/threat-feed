---
title: Command Injection in Deno node:child_process Module
slug: 2026-09-deno-command-injection
description: Deno versions 2.7.0 through 2.9.7 on Windows are vulnerable to command injection in the node:child_process module due to improper shell argument escaping.
date: "2026-09-30T18:36:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:deno:deno:2.7.0:*:*:*:*:*:*:*
  - cpe:2.3:a:deno:deno:2.9.7:*:*:*:*:*:*:*
tags:
  - vulnerability
  - command-injection
  - deno
  - windows
vendors:
  - Deno
products:
  - Deno (2.7.0 through 2.9.7)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Deno versions 2.7.0 through 2.9.7 on Windows contain a command injection vulnerability in node:child_process where shell arguments are escaped for the wrong shell type.
    confidence_band: high
cves:
  - id: CVE-2026-103473
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103473
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade Deno to version 2.9.8 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-103473 indicates a patch is available in subsequent versions.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Deno on Windows systems to 2.9.8+.
      owner: IT Operations
      addresses: CVE-2026-103473
      evidence: NVD vulnerability notice
---

Deno versions 2.7.0 through 2.9.7 on Windows contain a critical command injection vulnerability within the built-in node:child_process module. This flaw occurs because the implementation fails to correctly escape shell arguments when the shell option is enabled, causing the environment to process inputs for the incorrect shell type. An attacker capable of influencing the arguments passed to a child process via this module can escape the intended command context to execute arbitrary operating system commands. This execution occurs with the same privileges as the Deno runtime process. This vulnerability is particularly impactful for server-side applications, build tools, or automated workflows written in Deno that process external or untrusted data using the child_process spawning utilities.

## Impact

Successful exploitation allows for unauthorized arbitrary command execution on the host Windows system. This could lead to full system compromise, data exfiltration, or lateral movement depending on the service account context running the Deno application. Organizations using these specific Deno versions on Windows should prioritize upgrading to a patched release.

## Recommendation

- Upgrade all Deno instances on Windows to version 2.9.8 or later, where the shell argument escaping logic has been corrected.
- Audit Deno application codebases to identify instances where the node:child_process module is used with the 'shell' option and where untrusted input is passed to the argument array.
- Apply the principle of least privilege by running Deno processes under service accounts with limited filesystem and network permissions to mitigate the impact of potential command injection.
