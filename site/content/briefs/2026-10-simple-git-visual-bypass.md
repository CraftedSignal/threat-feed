---
title: Security-Control Bypass in @simple-git/argv-parser via Unfiltered VISUAL Environment Variable
slug: 2026-10-simple-git-visual-bypass
description: The @simple-git/argv-parser library fails to classify the VISUAL environment variable as an unsafe editor, allowing attackers to bypass security guards and execute arbitrary code during Git operations.
date: "2026-10-06T00:41:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - security-bypass
  - code-execution
  - git
  - supply-chain
vendors:
  - simple-git
products:
  - '@simple-git/argv-parser (<= 1.1.1)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'Git falls back to VISUAL when resolving an editor, so parseEnv({ VISUAL: ''/tmp/evileditor'' }) reports no vulnerability while an interactive Git operation will execute that binary.'
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - Development
    - Security Engineering
  immediate_actions:
    - action: Audit applications using @simple-git for environment variable injection vulnerabilities.
      owner: Security Engineering
      due: 48h
      evidence: The impact is dependent on the consuming application's data flow.
  mitigation_plan:
    - priority: immediate
      action: 'Manually add ''visual'': ''allowUnsafeEditor'' to GitEnvKeys in packages/argv-parser/src/env/parse-env.ts.'
      owner: Development
      addresses: Security-control bypass via VISUAL variable
      evidence: Suggested remediation in the source advisory.
---

The @simple-git/argv-parser library (version 1.1.1 and earlier) contains a security-control bypass vulnerability in its unsafe editor detection mechanism. The library provides a plugin, `blockUnsafeOperationsPlugin`, intended to prevent the execution of attacker-influenced binaries by restricting environment variables that Git uses to resolve editors, such as `EDITOR`, `GIT_EDITOR`, and `GIT_SEQUENCE_EDITOR`. 

However, the parser's denylist implementation at `packages/argv-parser/src/env/parse-env.ts` fails to include the `VISUAL` environment variable. Furthermore, the `prepareEnv` function filters environment variables by checking if they exist in the `GitEnvKeys` map or start with the `git` prefix. Because `VISUAL` is neither in the map nor prefixed with `git`, it is discarded before the vulnerability scanner can evaluate it. Since Git falls back to `VISUAL` when resolving an editor, an attacker can supply a malicious binary path via this variable to gain code execution as the host user, bypassing the intended security guard.

## Attack Chain

1. Attacker identifies a target application that uses `@simple-git/argv-parser` and allows user-controlled input to influence the environment variables passed to a spawned Git process.
2. Attacker crafts a malicious environment object containing `VISUAL=/tmp/evileditor` and a `TERM` variable (set to a value other than 'dumb').
3. Attacker triggers a Git operation that requires an editor, such as `git commit --amend` or `git rebase -i`.
4. The application passes the attacker-influenced environment to `parseEnv` for security validation.
5. `prepareEnv` drops the `VISUAL` key because it is not recognized as a known Git environment key or prefixed with 'git'.
6. The `vulnerabilityCheck` function returns an empty list, incorrectly signaling that the operation is safe.
7. The application executes the Git child process with the attacker's environment.
8. Git resolves the editor using the `VISUAL` variable, launching the attacker's binary against repository files (e.g., `.git/COMMIT_EDITMSG`) with the privileges of the host user.

## Impact

The vulnerability allows an attacker to execute arbitrary binaries under the context of the user running the Git process. This leads to potential command execution, unauthorized modification of repository data, and potential lateral movement if the process runs in a privileged or CI/CD environment. The impact is dependent on the consuming application's data flow, specifically whether untrusted user input is allowed to modify the child process environment.

## Recommendation

1. Patch the application by updating `@simple-git/argv-parser` once a fix is released by the maintainer.
2. Apply a temporary hotfix to `packages/argv-parser/src/env/parse-env.ts` by adding `'visual': 'allowUnsafeEditor'` to the `GitEnvKeys` mapping.
3. Update `docs/PLUGIN-UNSAFE-ACTIONS.md` to reflect that `VISUAL` is now considered an unsafe editor variable.
4. Audit consuming applications to ensure that user-supplied input is not directly forwarded into the environment of child processes.
5. Consider explicitly setting a safe `core.editor` or `GIT_EDITOR` in the Git environment to override the `VISUAL` variable, effectively disabling the attacker's fallback.
