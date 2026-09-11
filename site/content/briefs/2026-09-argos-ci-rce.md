---
title: OS Command Injection in @argos-ci/core via CI Branch Names
slug: 2026-09-argos-ci-rce
description: The @argos-ci/core package is vulnerable to OS command injection when processing unvalidated branch or reference names in environments where hasRemoteContentAccess is disabled, allowing arbitrary code execution on CI runners.
date: "2026-09-11T00:54:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ci-cd
  - command-injection
  - supply-chain
vendors:
  - Argos
products:
  - '@argos-ci/core (<= 6.2.0)'
  - '@argos-ci/cli'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: The gitFetch() function passes user-controlled ref strings directly into an execSync() template literal which invokes /bin/sh -c.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-4x45-gxvp-6283
action_plan:
  priority: elevated
  owners:
    - DevOps
    - Security Engineering
  immediate_actions:
    - action: Audit CI pipeline configurations for Argos projects to determine if hasRemoteContentAccess is set to false
      owner: DevOps
      due: 24h
      evidence: This configuration triggers the vulnerable code path.
  mitigation_plan:
    - priority: immediate
      action: Upgrade @argos-ci/core to the latest patched version
      owner: DevOps
      addresses: CWE-78 / OS Command Injection
      evidence: Vulnerability exists in 6.2.0 and earlier.
---

The @argos-ci/core package (version 6.2.0 and earlier) contains an OS command injection vulnerability located in the git interaction logic. When a project is configured with `hasRemoteContentAccess: false`, the Argos upload process triggers local Git commands, including `git fetch` and `git merge-base`, via Node.js `execSync` calls. The vulnerability arises because the branch name (`input.ref`) and other input parameters are interpolated into command strings without any sanitization or escaping.

Since `execSync` spawns a `/bin/sh` shell to execute the command, shell metacharacters provided in the CI branch name (such as `$()`, backticks, or `;`) are interpreted and executed by the shell before the `git` process begins. An attacker who can influence the CI environment variables or the branch name of a triggered build - such as via a pull request - can execute arbitrary OS commands on the CI runner. This allows for the theft of repository secrets, tampering with build artifacts, or lateral movement within the CI infrastructure.

## Attack Chain

1. Attacker creates a malicious pull request or branch name containing shell metacharacters, such as `main$(touch /tmp/pwned)`.
2. The CI pipeline initiates an Argos upload process within an environment where `hasRemoteContentAccess` is set to `false`.
3. The `argos` CLI reads the malicious environment variable (e.g., `GITHUB_HEAD_REF` or `ARGOS_BRANCH`) and passes it into the internal `config` object.
4. The `upload.ts` module calls `getMergeBaseCommitSha()` using the attacker-controlled branch name as the `head` parameter.
5. The `gitFetch()` function in `packages/core/src/ci-environment/git.ts` receives the malicious string as the `ref` input.
6. The `execSync()` function interpolates the malicious branch string into a shell command template literal.
7. The underlying `/bin/sh` shell evaluates the embedded command substitution, executing the attacker's payload on the CI runner.

## Impact

Successful exploitation results in full OS command execution on the build runner with the permissions of the CI agent process. This typically includes access to sensitive environment variables (API keys, cloud credentials, and repository secrets). Organizations using Argos in CI environments without external remote access verification are at risk, particularly those that process builds from untrusted contributors or forks.

## Recommendation

1. Upgrade to a version of `@argos-ci/core` that replaces vulnerable `execSync` template-literal invocations with `execFileSync` using discrete argument arrays to prevent shell interpolation.
2. In the interim, implement strict input validation on all CI branch and reference environment variables to allow only alphanumeric characters, dashes, and underscores.
3. Review CI pipeline configurations to ensure that runners executing `argos upload` do not have access to sensitive secrets, or migrate to workflows that utilize `hasRemoteContentAccess: true` to avoid the vulnerable local Git code path.
