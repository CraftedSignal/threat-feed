---
title: GitPython Repository Discovery Vulnerability Leading to RCE
slug: 2026-10-gitpython-rce
description: GitPython versions up to 3.1.59 are vulnerable to an arbitrary code execution flaw where malicious tracked repository content is misidentified as a Git directory, causing hooks to execute during standard repository operations.
date: "2026-10-01T04:21:35Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gitpython_project:gitpython:*:*:*:*:*:*:*:*
  - cpe:2.3:a:gitpython_project:gitpython:*:*:*:*:*:python:*:*
tags:
  - remote-code-execution
  - gitpython
  - software-vulnerability
vendors:
  - GitPython
products:
  - GitPython (<= 3.1.59)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker-controlled repository can be made to execute arbitrary commands via the tracked <root>/hooks/pre-commit when the victim calls index.commit().
    confidence_band: high
cves:
  - id: CVE-2026-87817
    cvss: 8.8
    epss: 0.00405
references:
  - https://github.com/advisories/GHSA-239g-whfq-7xj9
action_plan:
  priority: elevated
  owners:
    - SOC
    - Engineering
  immediate_actions:
    - action: Audit codebase for GitPython usage in automated pipelines
      owner: Engineering
      due: 48h
      evidence: GitPython identified as the vulnerable component in CVE-2026-87817.
  mitigation_plan:
    - priority: immediate
      action: Upgrade GitPython to 3.1.60 or later
      owner: Engineering
      addresses: CVE-2026-87817
      evidence: Source explicitly identifies vulnerability in versions <= 3.1.59.
---

GitPython versions through 3.1.59 contain a flaw in the `Repo.__init__` discovery logic that incorrectly resolves the git directory. The library tests candidate paths in an order that prioritizes arbitrary files over the actual `.git` directory. An attacker can place specially crafted files, including `hooks/`, `HEAD`, `config`, and `commondir`, at the root of a tracked repository. When a victim uses GitPython to clone or interact with this repository, the library misidentifies the working-tree root as the git directory. This allows the attacker to gain code execution by placing an executable `pre-commit` hook in the repository, which is triggered when `index.commit()` is called. Additionally, the library's misidentification allows for arbitrary file reading via malicious `config` includes, as the parser follows relative paths to sensitive files such as `~/.aws/credentials`. This vulnerability affects automated systems like CI runners, code-scanning services, and AI agents that process untrusted repositories.

## Attack Chain

1. Attacker creates a repository containing tracked files named `gitdir`, `commondir`, and `HEAD` at the root.
2. Attacker places a malicious executable script in `hooks/pre-commit` (mode 100755).
3. Victim application clones or opens the attacker-controlled repository using `git.Repo()`.
4. GitPython discovery logic iterates through the root files and incorrectly resolves the working-tree root as the git directory.
5. GitPython sets the internal `git_dir` to the attacker's chosen path.
6. Victim application calls `index.commit()`, prompting GitPython to search for and execute hooks from the misidentified path.
7. The `pre-commit` hook executes with the permissions of the victim process.

## Impact

Successful exploitation allows for arbitrary code execution in the context of the user or service running the GitPython library. This impacts automated CI/CD pipelines, code analysis services, and developer workstations. The vulnerability also enables unauthorized file disclosure by forcing the parser to merge malicious git configuration files, potentially exfiltrating sensitive credentials or system files.

## Recommendation

1. Upgrade GitPython to a patched version once available (as of publication, versions <= 3.1.59 are confirmed vulnerable).
2. Avoid processing untrusted or unverified repositories using GitPython `index.commit()` or similar methods that trigger hook execution.
3. For CI/CD and automated pipelines, implement strict sandboxing or containerization when running GitPython to minimize the impact of potential command execution.
4. Audit internal codebases for usage of `git.Repo.clone_from` or `git.Repo()` where the source repository is provided by external or untrusted users.
