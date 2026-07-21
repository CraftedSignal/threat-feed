---
title: Gitea Actions Fork Pull Request Approval Gate Bypass
slug: 2026-07-gitea-fork-pr-bypass
description: A vulnerability in Gitea Actions (versions v1.20.0 and later) allows an unprivileged attacker to permanently bypass the fork pull request approval gate for a repository after a single, initial workflow approval, enabling arbitrary shell command execution on the Gitea Actions runner without further maintainer interaction, leading to source code disclosure and potential system compromise.
date: "2026-07-21T20:43:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - logic-bug
  - ci-cd
  - code-execution
  - privilege-escalation
  - gitea-actions
vendors:
  - Gitea
products:
  - Gitea (v1.20.0 and later)
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability in Gitea Actions allows an attacker to bypass the fork pull request approval gate. After a repository administrator approves a single, benign fork PR's workflow from an attacker, all subsequent fork PRs from that same attacker on the same repository will automatically bypass the approval gate.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This enables the attacker to execute arbitrary shell commands on the Gitea Actions runner without any further maintainer interaction.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: gaining control over the runner's environment, including access to the cloned source, environment variables like GITHUB_TOKEN, and outbound network capabilities.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Source code disclosure... with outbound network access
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-777r-4v59-6486
---

A critical logic flaw, identified as GITEA-2026-004, has been discovered in Gitea Actions affecting all versions v1.20.0 and later. This vulnerability allows an unprivileged Gitea user with the ability to fork a repository to bypass the intended approval mechanism for fork pull requests. The flawed logic, introduced in commit `edf98a2dc3` (February 24, 2023), mistakenly interprets a single approval of any workflow run from a contributor on a given repository as permanent, unconditional trust for that user on that repository. Consequently, after a repository administrator approves a single benign pull request's workflow from an attacker, all subsequent malicious pull requests from the same attacker on the same repository will automatically execute their workflows on the Gitea Actions runner without requiring any further maintainer intervention. This effectively grants the attacker arbitrary code execution capabilities on the runner, leading to potential source code disclosure, exfiltration of sensitive data, or broader system compromise.

## Attack Chain

1. An attacker creates an unprivileged Gitea account on a self-hosted Gitea instance.
2. The attacker forks a target repository, typically a public project or one they wish to compromise.
3. The attacker submits a benign pull request (PR) from their fork to the target repository, triggering a Gitea Actions workflow. This PR's workflow is designed to appear harmless and gain initial approval.
4. A repository administrator reviews the benign PR and, unaware of the vulnerability, explicitly approves its workflow run.
5. Gitea's flawed `ifNeedApproval()` function (in `services/actions/notifier_helper.go`) records this approval as a permanent trust for the attacker's user ID on that repository by incrementing `approved_by` in the `action_run` table.
6. The attacker then creates a new branch in their fork and crafts a second, malicious pull request containing a harmful workflow file (e.g., executing shell commands like `curl`, `id`, `ls -la` to exfiltrate data or establish persistence).
7. Due to the previously recorded permanent trust, Gitea's approval gate is bypassed, and the malicious workflow is dispatched immediately to the configured Gitea Actions runner without any further interaction or explicit approval from the maintainer.
8. The Gitea Actions runner executes the malicious workflow, granting the attacker arbitrary shell execution, access to the cloned source code, environment variables (like a populated `GITHUB_TOKEN`), and outbound network connectivity, leading to various impacts.

## Impact

The successful exploitation of this vulnerability results in arbitrary code execution on the Gitea Actions runner environment. This gives attackers control over the CI compute resources with the ambient privileges of the runner (shell access, network connectivity, filesystem access). Observed consequences include the ability to execute arbitrary shell commands, access to a populated `GITHUB_TOKEN` which can be used to interact with the Gitea API, and source code disclosure from the cloned repository. Attackers can leverage this access to exfiltrate sensitive data, manipulate repository contents, compromise the runner infrastructure itself, or establish further footholds within the organization's network. While the number of affected instances is not specified, all self-hosted Gitea instances running v1.20.0 or later are potentially vulnerable, impacting any organization utilizing Gitea Actions for CI/CD.

## Recommendation

* If possible, temporarily disable Gitea Actions for fork pull requests on sensitive repositories until a patch is available.
* Implement a rigorous review process for any first-time contributor's pull request, including manual verification of workflow files and their potential impact, even if only a one-time approval is required.
* Monitor Gitea application logs for `action_run` entries where `need_approval` is `false` but `approved_by` is `0` for new fork pull requests, which could indicate exploitation.
* Monitor Gitea Actions runner activity for suspicious shell commands (e.g., `curl` to unusual destinations, `id`, `ls -la` in unexpected directories) originating from fork PR workflows, which would be visible in the runner's execution logs (`/api/v1/repos/{owner}/{repo}/actions/jobs/{job_id}/logs`).
