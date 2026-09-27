---
title: Command Injection in navi via Cheatsheet Variable Substitution
slug: 2026-09-navi-command-injection
description: navi version 2.24.0 and earlier contains a command injection vulnerability due to improper escaping of cheatsheet variable values, allowing arbitrary command execution via crafted file names.
date: "2026-09-27T15:07:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:navi_project:navi:*:*:*:*:*:*:*:*
vendors:
  - navi
products:
  - navi (<= 2.24.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can inject shell metacharacters through crafted file names in suggestion command directories to execute arbitrary commands with victim privileges.
    confidence_band: high
cves:
  - id: CVE-2026-101032
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101032
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Restrict write access to directories defined as navi suggestion command paths.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-101032
  mitigation_plan:
    - priority: immediate
      action: Upgrade navi to a version beyond 2.24.0.
      owner: IT Operations
      addresses: CVE-2026-101032
      evidence: NVD vulnerability disclosure
---

navi version 2.24.0 and earlier contains a command injection vulnerability (CVE-2026-101032) resulting from the failure to properly escape cheatsheet variable values when substituting them into shell commands. An attacker can create a malicious file name within a suggestion command directory that contains shell metacharacters. When the navi utility processes these directories and consumes the file names as variables, the injected metacharacters are interpreted by the underlying shell, leading to arbitrary command execution with the privileges of the user running navi. This vulnerability affects users of the navi command-line interactive cheatsheet tool on Linux and macOS environments. Defending against this requires updating to a patched version once available and restricting write access to directory paths monitored by navi for cheatsheet suggestions.

## Impact

Successful exploitation allows an unauthenticated attacker to execute arbitrary shell commands on the host system. Given that navi is often used by developers and system administrators to manage and execute complex commands, this could lead to full compromise of the user account, lateral movement, or unauthorized access to sensitive local files and environment variables.

## Recommendation

* Monitor system logs for unexpected child processes spawned by the 'navi' binary or its sub-processes.
* Audit directories configured for use by navi as suggestion command sources; ensure only trusted users have write access to these locations.
* Upgrade to the patched version of navi (post-2.24.0) once released by the vendor to resolve the command injection flaw in variable substitution.
