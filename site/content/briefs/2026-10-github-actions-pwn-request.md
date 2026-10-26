---
brief_id: brief-2026-10-26-github-actions-pwn-request
event_id: brief-2026-10-26-github-actions-pwn-request
revision: 1
activity_at: "2026-10-26T16:13:19Z"
title: 'GitHub Actions: Residual vulnerabilities in pull_request_target and workflow triggers'
slug: 2026-10-github-actions-pwn-request
description: Despite 2026 platform security improvements, GitHub Actions workflows remain vulnerable to code execution via misconfigured event triggers, direct git CLI calls, script injection, and cross-workflow artifact poisoning.
date: "2026-10-26T16:13:19Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment-specific audit
tags:
  - supply-chain
  - ci-cd
  - cloud-security
vendors:
  - GitHub
products:
  - GitHub Actions
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
    evidence: When workflow authors interpolate event context directly into shell commands using ${{ }} expressions, GitHub substitutes the value into the script before the shell runs.
    confidence_band: high
references:
  - https://www.wiz.io/blog/github-actions-security-pwn-request-reckoning
action_plan:
  priority: elevated
  owners:
    - DevSecOps
  immediate_actions:
    - action: Audit all repository workflows for usage of pull_request_target, workflow_run, and issue_comment triggers.
      owner: DevSecOps
      due: 48h
      evidence: Source documentation of persistent risk in these specific triggers.
  hunt_leads:
    - lead: Identify workflows using direct git CLI commands or third-party checkout actions for fetching fork code.
      technique_id: T1059
      data_needed:
        - GitHub Workflow YAML configuration files
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Direct git CLI invocations sidestep protections entirely.
  mitigation_plan:
    - priority: immediate
      action: Upgrade actions/checkout to v7.0.0 or the specified backported versions.
      owner: DevOps
      addresses: GitHub Actions checkout protections
      evidence: GitHub's backported protections rely on logic embedded within actions/checkout itself.
---

GitHub implemented several security controls throughout 2026 to mitigate 'Pwn request' vulnerabilities, where untrusted fork code could execute with repository secrets. These protections include fork checkout restrictions in `actions/checkout@v7`, read-only cache tokens, and workflow execution policies. However, these controls are not universal and can be bypassed through specific workflow misconfigurations. Vulnerabilities persist in workflows using non-default event triggers, manual git cloning, direct shell interpolation of event context, and persistent artifacts or runner state.

## Attack Chain
1. Actor submits a malicious pull request to a target repository or comments on an issue to trigger a workflow.
2. The target repository's CI workflow fires, triggered by `pull_request_target`, `workflow_run`, or `issue_comment`.
3. The workflow uses an outdated or SHA-pinned version of `actions/checkout` (pre-July 2026) that lacks fork protection, or uses `git` CLI/third-party actions to bypass the protection logic.
4. The malicious code is checked out or downloaded into the workflow workspace.
5. The workflow executes the untrusted code or scripts in an environment containing elevated secrets (e.g., `GITHUB_TOKEN`, `DEPLOY_KEY`).
6. The actor achieves unauthorized code execution, exfiltrating secrets or poisoning downstream build artifacts.

## Impact
Successful exploitation allows attackers to gain code execution within the context of a target repository's CI/CD pipeline. This grants access to repository secrets, enables the exfiltration of sensitive build data, and permits the injection of malicious code into subsequent deployment or release artifacts.

## Recommendation
- Update all `actions/checkout` references to version v7.0.0 or higher.
- If using SHA pinning, ensure the pinned SHAs correspond to patched versions (v2.8.0, v3.7.0, v4.4.0, v5.1.0, v6.1.0, or v7.0.0+).
- Replace direct `git clone`, `gh pr checkout`, or `gh repo clone` commands with approved, hardened checkout actions.
- Never interpolate event context directly into shell commands; pass all untrusted inputs through environment variables.
- Implement authorization checks for `issue_comment` and `repository_dispatch` triggers, verifying that the actor has appropriate repository permissions.
- Transition to ephemeral runners to prevent cross-workflow state poisoning on self-hosted environments.
