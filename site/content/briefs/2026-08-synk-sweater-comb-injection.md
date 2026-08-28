---
title: Command Injection in Synk Sweater Comb
slug: 2026-08-synk-sweater-comb-injection
description: Synk Sweater Comb before version 3.8.8 contains a command injection vulnerability in the expectGitBranch() function, allowing arbitrary OS command execution via crafted .vervet.yaml configuration files.
date: "2026-08-28T21:37:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:synk:sweater_comb:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - ci-cd-security
vendors:
  - Synk
products:
  - Sweater Comb (< 3.8.8)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The expectGitBranch() function in src/lint.ts passes the unsanitized branch name directly into child_process.exec() via an unescaped template literal, enabling arbitrary command execution.
    confidence_band: high
cves:
  - id: CVE-2026-75486
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75486
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development Security
  immediate_actions:
    - action: Upgrade Synk Sweater Comb to 3.8.8
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-75486 remediation
  mitigation_plan:
    - priority: immediate
      action: Upgrade Synk Sweater Comb to 3.8.8
      owner: IT Operations
      addresses: CVE-2026-75486
      evidence: NVD vulnerability report
---

Synk Sweater Comb versions prior to 3.8.8 are vulnerable to a command injection flaw originating from the processing of the .vervet.yaml configuration file. The vulnerability exists within the expectGitBranch() function located in src/lint.ts, where user-supplied input from the 'linters.&lt;key>.optic-ci.original' branch name field is concatenated directly into a template literal. This unsanitized string is then passed to the Node.js child_process.exec() function. An attacker who can influence the contents of the repository's configuration file can gain arbitrary OS command execution privileges when a victim executes the linting process. This flaw allows for lateral movement, data exfiltration, or persistence on the developer workstation or CI/CD runner environment where the tool is executed. Defenders should prioritize updating Synk Sweater Comb to version 3.8.8 or higher.

## Attack Chain

1. Attacker gains write access to a repository containing a .vervet.yaml configuration file.
2. Attacker modifies the 'linters.&lt;key>.optic-ci.original' field within the .vervet.yaml file.
3. Attacker injects shell metacharacters and arbitrary commands into the branch name string.
4. Victim triggers the Synk Sweater Comb linting process within the directory.
5. The expectGitBranch() function reads the malicious branch name from the configuration file.
6. The unsanitized input is passed directly to the shell via child_process.exec().
7. The operating system executes the attacker-supplied commands with the privileges of the user running the lint command.

## Impact

Successful exploitation allows for remote code execution on the target system. This could lead to a full compromise of a developer's workstation or a CI/CD build pipeline, potentially resulting in unauthorized access to source code, secrets, or internal network segments if the runner is improperly scoped.

## Recommendation

1. Upgrade Synk Sweater Comb to version 3.8.8 or later immediately to patch the command injection vulnerability in src/lint.ts.
2. Audit all repositories using .vervet.yaml for suspicious branch name fields or injected shell syntax (e.g., semicolons, pipe characters, backticks).
3. Limit the permissions of CI/CD runners to ensure that if arbitrary code execution occurs, the attacker cannot reach sensitive internal resources.
