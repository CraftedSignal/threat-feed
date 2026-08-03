---
title: GitPython Argument Injection in IndexFile and TagReference
slug: 2026-08-gitpython-argument-injection
description: GitPython fails to sanitize keyword arguments passed to git commands, allowing attackers to perform arbitrary file overwrites and unauthorized file reads.
date: "2026-08-03T20:47:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - injection
  - python
  - gitpython
  - supply-chain
vendors:
  - GitPython
products:
  - GitPython (<= 3.1.56)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The library forwards kwargs to git-checkout-index, which can be exploited to overwrite files and execute code via hooks or config overrides.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - AppSec
  immediate_actions:
    - action: Review all instances of GitPython usage in the codebase for potential exposure to user-controlled kwargs
      owner: AppSec
      due: 48h
      evidence: Source document identifies 14 unguarded call sites
  mitigation_plan:
    - priority: immediate
      action: Implement mandatory sanitization for git kwargs in all GitPython calls
      owner: IT Operations
      addresses: GitPython (<= 3.1.56)
      evidence: Suggested remediation section recommends allow_unsafe_options gating
---

GitPython, a library widely used for interacting with Git repositories in Python applications, contains critical argument injection vulnerabilities in its `IndexFile.checkout()` and `TagReference.create()` methods. These methods forward user-provided keyword arguments (`**kwargs`) directly to the underlying `git` command-line utility without sufficient validation of dangerous options.

An attacker capable of influencing the arguments passed to these methods can trigger unauthorized filesystem operations. In `IndexFile.checkout()`, the lack of filtering for the `--prefix` option allows for arbitrary file overwriting, potentially resulting in remote code execution if the attacker can overwrite configuration files, SSH keys, or application scripts. In `TagReference.create()`, the lack of filtering for `-F` or `--file` options allows an attacker to read the contents of arbitrary files accessible to the application's service account, returning the data through the library's tag message interface. This issue persists in all versions of GitPython up to and including 3.1.56.

## Attack Chain

1. An attacker identifies a target application using a vulnerable version of GitPython (3.1.56 or earlier).
2. The application exposes an interface where user-controlled input influences arguments passed to `IndexFile.checkout()` or `TagReference.create()`.
3. The attacker crafts a payload containing dangerous git flags (e.g., `--prefix` for overwrite or `--file` for read).
4. The application processes the malicious input and passes the flags as keyword arguments to the vulnerable GitPython method.
5. GitPython internally invokes the `git` binary, appending the attacker's flags to the command line.
6. The `git` process executes with the privileges of the application's service account, applying the malicious flags to the filesystem.
7. Final impact: The attacker achieves unauthorized file read disclosure or arbitrary file overwrite, potentially leading to system compromise.

## Impact

Successful exploitation allows attackers to overwrite critical system files or exfiltrate sensitive data. An attacker could overwrite files such as `~/.ssh/authorized_keys` or `post-checkout` hooks to achieve persistence and code execution. The file read vulnerability enables the exfiltration of credentials, configuration files, and secrets. Because these operations occur at the privilege level of the application running the GitPython library, the potential damage is significant in both cloud-native environments and CI/CD pipelines.

## Recommendation

- Upgrade GitPython to the latest version as soon as a patch is available.
- Implement a wrapper for all GitPython calls that use `**kwargs` to explicitly validate against a deny-list of dangerous git options like `--prefix`, `--file`, `-F`, `-s`, and `-u`.
- Enforce strict input validation on all user-supplied data that reaches GitPython methods to prevent the injection of arbitrary git flags.
- Monitor application logs for execution of git commands that include suspicious flags or path references originating from the application process.
