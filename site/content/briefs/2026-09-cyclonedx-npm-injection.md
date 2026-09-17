---
title: Command Injection in @cyclonedx/cyclonedx-npm via --workspace Argument
slug: 2026-09-cyclonedx-npm-injection
description: A command injection vulnerability in @cyclonedx/cyclonedx-npm on Windows allows attackers to execute arbitrary commands by supplying malicious input to the --workspace argument.
date: "2026-09-17T19:15:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cyclonedx:cyclonedx_cyclonedx_npm:*:*:*:*:*:*:*:*
tags:
  - command-injection
  - supply-chain
  - windows
vendors:
  - CycloneDX
products:
  - '@cyclonedx/cyclonedx-npm (< 6.0.0)'
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The tool's fallback execution path improperly handles shell metacharacters, allowing an attacker to execute arbitrary OS commands.
    confidence_band: high
cves:
  - id: CVE-2026-71538
references:
  - https://github.com/advisories/GHSA-q69g-4hcv-6jg4
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71538
rules:
  - title: Detect Suspicious Command Line Arguments in cyclonedx-npm
    description: Detects potential command injection attempts via the --workspace argument in cyclonedx-npm by identifying shell metacharacters in the command line
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade @cyclonedx/cyclonedx-npm to 6.0.0 or later
      owner: IT Operations
      due: 48h
      evidence: Source states fix is included in 6.0.0
  mitigation_plan:
    - priority: immediate
      action: Set npm_execpath environment variable to a valid npm-cli.js path
      owner: IT Operations
      addresses: CVE-2026-71538
      evidence: Source suggests this as a temporary mitigation
---

The npm package `@cyclonedx/cyclonedx-npm` is vulnerable to command injection on Windows systems. The vulnerability resides in how the CLI tool handles the `--workspace` argument. In the tool's fallback execution path, user-supplied input provided to the `--workspace` flag is passed directly to the system shell without sufficient sanitization or neutralization of shell metacharacters. 

An attacker who can control or influence the value passed to the `--workspace` flag can inject shell metacharacters such as `&`, `|`, or `>` to break out of the intended command context. This allows for the execution of arbitrary OS commands with the privileges of the user running the CLI tool. This vulnerability was addressed in version 6.0.0 by moving away from the vulnerable fallback path and ensuring input is handled safely.

## Impact

Successful exploitation allows for arbitrary command execution on the host machine. This can result in data exfiltration, unauthorized modification of files, or elevation of local privileges depending on the user's current environment. The impact is limited to Windows systems where the vulnerable fallback path is reachable.

## Recommendation

* Upgrade the `@cyclonedx/cyclonedx-npm` package to version 6.0.0 or later to apply the fix for CVE-2026-71538.
* Audit build pipelines and development workflows that invoke this tool to ensure that user-supplied input is not being passed to the `--workspace` argument.
* On Windows, if upgrading is not immediately feasible, restrict the use of the tool to trusted inputs only and consider setting the `npm_execpath` environment variable to point to a known safe `npm-cli.js` to potentially bypass the vulnerable fallback path.
