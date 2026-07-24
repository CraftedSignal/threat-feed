---
title: GitPython Incomplete Denylist Allows Arbitrary Command Execution via Git Clone Hooks
slug: 2026-07-gitpython-unsafe-git-clone-options
description: A critical vulnerability in GitPython versions up to 3.1.53 allows attackers to achieve arbitrary command execution by influencing `git clone` options to include a malicious `--template` directory, which causes Git hooks to be copied and executed during cloning, even in default configurations.
date: "2026-07-24T16:45:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - git
  - python
  - vulnerability
  - rce
vendors:
  - GitPython
products:
  - GitPython <= 3.1.53
affected_os:
  - windows
  - linux
  - macos
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: git copies the hook directory and executes `post-checkout` at checkout time.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: git copies the hook directory and executes `post-checkout` at checkout time.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: git copies the hook directory and executes `post-checkout` at checkout time.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6p8h-3wgx-97gf
rules:
  - title: Detect GitPython Unsafe Template Arbitrary Command Execution
    description: Detects exploitation of the GitPython vulnerability where the `--template` option is used with the `git clone` command, potentially indicating arbitrary command execution via malicious Git hooks.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.004
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

A high-severity vulnerability exists in GitPython versions up to and including 3.1.53, stemming from an incomplete denylist within the `unsafe_git_clone_options` mechanism. Specifically, the `--template` option for `git clone` is not blocked, allowing an attacker to specify a path to an attacker-controlled directory containing malicious Git hooks. When GitPython executes the underlying `git clone` command, these hooks, such as `post-checkout`, are copied into the new repository and subsequently executed during the checkout phase. This oversight leads to arbitrary command execution on the system hosting the GitPython application. The exploitation requires the attacker to provide an attacker-readable directory containing an executable hook, which can be realistic via shared filesystems, upload directories, or attacker-writable network paths. This flaw impacts all platforms where GitPython is used.

## Attack Chain

1. Attacker crafts a malicious Git hook script (e.g., `post-checkout`) containing commands designed for arbitrary execution on the victim's system.
2. Attacker places this malicious script into a specially structured directory, such as `<attacker_controlled_path>/hooks/post-checkout`, ensuring it has executable permissions.
3. Attacker identifies a vulnerable GitPython application that performs `Repo.clone_from` operations and can be manipulated to accept an attacker-controlled value for the `template` argument.
4. The vulnerable GitPython application is tricked into initiating a `Repo.clone_from` call, passing the attacker-controlled path to the `template` parameter.
5. GitPython's internal `check_unsafe_options` function, intended to prevent dangerous `git clone` options, fails to block `--template` because it is missing from its `unsafe_git_clone_options` denylist.
6. The underlying `git` command is executed on the host system, including the `--template=<attacker_controlled_path>` option.
7. The `git` command copies the malicious `post-checkout` hook from `<attacker_controlled_path>/hooks/` to the newly cloned repository's `.git/hooks/` directory.
8. During the repository checkout process, which is part of the `git clone` operation, the newly copied malicious `post-checkout` hook is automatically executed, resulting in arbitrary command execution on the victim's system.

## Impact

Successful exploitation of this vulnerability leads to arbitrary operating system command execution on the host running the GitPython application. An attacker could leverage this to install malware, exfiltrate sensitive data, establish persistence, or further compromise the affected system and network. While a second precondition of an attacker-readable directory with an executable hook is necessary, this is considered achievable in many real-world scenarios. This vulnerability affects any system using vulnerable versions of GitPython, regardless of the underlying operating system.

## Recommendation

* Upgrade GitPython to a patched version once available.
* Implement host-based detection for unusual Git command-line parameters, specifically the `--template` option, by deploying the Sigma rule provided in this brief.
* Monitor process creation logs for `git.exe` or `git` processes executing with unusual arguments or child processes that deviate from expected behavior for Git operations.
* Restrict write permissions on directories that could be used by attackers to stage malicious Git hooks, such as temporary directories or shared network drives.
