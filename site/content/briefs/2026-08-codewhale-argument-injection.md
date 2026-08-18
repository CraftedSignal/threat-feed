---
title: Argument Injection Vulnerability in CodeWhale git_show Tool
slug: 2026-08-codewhale-argument-injection
description: An argument injection vulnerability (CVE-2026-75913) in the CodeWhale git_show tool allows attackers to perform arbitrary file writes under the user's privilege level by manipulating the 'rev' parameter.
date: "2026-08-18T16:55:25Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - CodeWhale
products:
  - codewhale (>= 0.8.41, < 0.8.64)
  - codewhale-tui (>= 0.8.41, < 0.8.64)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The model-supplied rev parameter is passed unvalidated into the git show argv without an --end-of-options sentinel, so a value beginning with --output= is interpreted as a git flag.
    confidence_band: high
cves:
  - id: CVE-2026-75913
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75913
rules:
  - title: Detect CVE-2026-75913 - Potential Argument Injection in git via CodeWhale
    description: Detects the use of the --output flag in git commands spawned by CodeWhale, indicating a potential attempt to exploit CVE-2026-75913 for arbitrary file write.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch all CodeWhale and codewhale-tui instances to version 0.8.64
      owner: IT Operations
      due: 48h
      evidence: Fixed in 0.8.64 by adding rev validation.
  mitigation_plan:
    - priority: immediate
      action: Deploy detection rule for git --output usage
      owner: Detection Engineering
      addresses: CVE-2026-75913
      evidence: The git_show tool... is vulnerable to argument injection
---

CodeWhale and codewhale-tui versions 0.8.41 through 0.8.63 contain an argument injection vulnerability within the `git_show` tool, assigned as CVE-2026-75913. The vulnerability stems from the tool failing to properly validate the `rev` parameter before passing it to the `git show` command line. By supplying an input starting with `--output=`, an attacker can inject malicious flags into the git execution process. Because the tool is registered for auto-approval and marketed as a read-only utility, it is often trusted by users and automated workflows. An attacker can leverage this trust, potentially in combination with prompt injection within a malicious repository, to cause the `git` binary to overwrite sensitive files such as `~/.ssh/authorized_keys`, `~/.bashrc`, or `~/.gitconfig` with attacker-controlled content. This flaw allows for lateral movement, persistence, or credential harvesting at the privilege level of the user executing the tool. The issue is resolved in version 0.8.64 by implementing input validation for the `rev` parameter.

## Impact

Successful exploitation allows for arbitrary file writes, enabling an attacker to gain persistence or modify system configurations on the host machine. This poses a significant risk to developers and automated CI/CD environments where CodeWhale is utilized, potentially leading to unauthorized access to developer environments or the execution of malicious commands via modified shell profiles.

## Recommendation

- Upgrade all instances of `codewhale` and `codewhale-tui` to version 0.8.64 or later immediately.
- Audit logs for the execution of `git` commands spawned by CodeWhale to identify anomalous command-line arguments, specifically those containing `--output=`.
- Restrict the permissions of users executing the CodeWhale tool to limit the potential impact of an arbitrary file write on sensitive user-specific configuration files.
