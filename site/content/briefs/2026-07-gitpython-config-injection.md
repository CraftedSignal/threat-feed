---
title: GitPython Arbitrary Config Injection via Submodule Name (GHSA-3rp5-jjmw-4wv2)
slug: 2026-07-gitpython-config-injection
description: A critical vulnerability in GitPython versions up to 3.1.52 allows attackers to inject arbitrary Git configuration directives into a victim's `.git/config` file by crafting a malicious submodule name, leading to remote code execution (RCE) during subsequent Git operations that trigger `core.sshCommand`.
date: "2026-07-24T16:33:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-injection
  - rce
  - python
  - git
  - supply-chain
products:
  - GitPython (<= 3.1.52)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Because a submodule name is attacker-controlled data (...) an attacker can set `core.sshCommand` (...) and achieve remote code execution on the victim's next git operation.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Arbitrary attacker-controlled write into the victim's repository-local `.git/config`, which git fully trusts. `core.sshCommand` is executed as the ssh transport command on the victim's next ssh git operation (fetch/pull/push), giving remote code execution; other injectable keys (`alias.*`, `core.pager`, `core.fsmonitor`) fire on more common operations.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-3rp5-jjmw-4wv2
---

A high-severity vulnerability (GHSA-3rp5-jjmw-4wv2) exists in the GitPython library, affecting all versions up to and including 3.1.52. This flaw enables attackers to achieve remote code execution (RCE) on a victim's system. The vulnerability stems from insufficient neutralization of special characters (specifically `]`, `[`, and `"`) in Git configuration section names. An attacker can craft a malicious submodule name, which, when processed by GitPython's config writer, leads to the injection of arbitrary configuration directives into the victim's `.git/config` file. This can be exploited through two primary vectors: an application using `Repo.create_submodule` with untrusted input, or by cloning an untrusted repository followed by `submodule_update`. Once injected, a directive like `core.sshCommand` can execute arbitrary code when the victim performs a subsequent Git operation (e.g., fetch, pull, push) that utilizes SSH, posing a significant threat to developers and CI/CD pipelines.

## Attack Chain

1. An attacker crafts a malicious submodule name, such as `'x"] [core] sshCommand=CMD #'`, designed to close the legitimate `[submodule "` section and open a new `[core]` section with an injected `sshCommand`.
2. The attacker convinces a victim to either use `Repo.create_submodule` with this malicious name (e.g., in a development tool or application accepting untrusted input) or to clone an untrusted Git repository containing this malicious submodule name in its `.gitmodules` file and then execute `submodule_update`.
3. GitPython's config writer (e.g., `fp.write(("[%s]\n" % name).encode(defenc))`) processes the crafted submodule name without adequately escaping the special characters.
4. The malicious name is written into the victim's repository-local `.git/config` file, resulting in an entry like `[submodule "x"] [core] sshCommand=CMD #"]`.
5. The Git client parses this malformed entry, treating `[core] sshCommand=CMD` as a valid configuration directive due to the unescaped `]` closing the `submodule` section and `[` opening a new `core` section on the same line.
6. The `core.sshCommand` configuration is now set to an attacker-controlled command (e.g., `CMD`).
7. Upon the victim's next Git operation that requires SSH (e.g., `git fetch`, `git pull`, `git push`), the configured `core.sshCommand` is executed by the system.
8. The attacker's command `CMD` is executed on the victim's machine, achieving remote code execution.

## Impact

Successful exploitation of this vulnerability grants attackers arbitrary code execution on the victim's system, operating under the privileges of the user executing the Git operation. This can lead to complete system compromise, data exfiltration, or further lateral movement within an organization's network. The attack is highly effective because it leverages Git's trusted configuration mechanism. It can be triggered by common Git operations like `fetch`, `pull`, or `push` that use SSH, affecting developers, CI/CD systems, and any environment processing Git repositories with GitPython. While primarily observed as a Unix vector for the `clone_from` + `submodule_update` path, the direct `create_submodule` API sink remains exploitable across Windows, Linux, and macOS platforms.

## Recommendation

* Upgrade GitPython to a version greater than 3.1.52 immediately to remediate GHSA-3rp5-jjmw-4wv2.
* Implement rigorous input validation and sanitization for any application that constructs Git submodules from untrusted input using `Repo.create_submodule`.
* Educate users to exercise caution when cloning or initializing submodules from untrusted or unfamiliar Git repositories, as this can be a vector for `core.sshCommand` injection.
* Monitor process creation logs for unusual commands executed by Git or SSH processes, as this could indicate RCE via an injected `core.sshCommand` (requires enabling Sysmon or similar granular logging).
