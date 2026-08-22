---
title: Command Injection in better-npm-audit via --registry Parameter
slug: 2026-08-better-npm-audit-injection
description: The better-npm-audit package is vulnerable to arbitrary command injection via improper sanitization of the --registry command-line argument when passed to a shell execution context.
date: "2026-08-22T13:30:26Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - better-npm-audit (3.11.0)
  - better-npm-audit (4.0.0-rc.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A registry value containing shell metacharacters such as a semicolon, pipe, or command substitution executes arbitrary operating system commands with the privileges of the process running the audit.
    confidence_band: high
cves:
  - id: CVE-2026-57998
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57998
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review CI/CD and developer workstation logs for CLI arguments containing shell metacharacters for the better-npm-audit process.
      owner: SOC
      due: 48h
      evidence: CVE-2026-57998 documentation of vulnerability vector.
  mitigation_plan:
    - priority: immediate
      action: Upgrade or replace vulnerable versions of better-npm-audit.
      owner: IT Operations
      addresses: CVE-2026-57998
      evidence: Package is vulnerable to command injection via input interpolation.
---

The better-npm-audit package (versions through 3.11.0 and 4.0.0-rc.2) contains a critical command injection vulnerability identified as CVE-2026-57998. The vulnerability originates in src/handlers/handleInput.ts, where user-supplied input provided via the --registry command-line option is directly interpolated into a command string without sufficient validation or quoting. This string is subsequently passed to child_process.exec() in index.ts, which triggers a shell-based execution context. By supplying shell metacharacters such as semicolons, pipes, or command substitution sequences, an attacker can execute arbitrary operating system commands. The injected commands run with the privileges of the user executing the audit process, which may include build agents or developer environments, posing a significant risk to CI/CD pipelines and local workstations.

## Impact

Successful exploitation allows for arbitrary code execution in the context of the user or process running the better-npm-audit tool. This can lead to full compromise of the local environment, exfiltration of credentials or source code, and persistent access to CI/CD systems, potentially facilitating supply chain compromise if injected into automated pipelines.

## Recommendation

* Upgrade better-npm-audit to a patched version that sanitizes the --registry input or switches from child_process.exec() to child_process.execFile() to avoid shell interpretation.
* Audit build logs and automated CI/CD pipeline configurations to detect suspicious usage of the --registry parameter containing shell metacharacters like ";", "|", "&", or "$".
* Limit the privileges of service accounts running audit tools in CI/CD environments to minimize the impact of successful command injection.
