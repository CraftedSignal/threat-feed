---
title: GitPython Command Injection via Unsafe Git Option Guard Bypass
slug: 2026-08-gitpython-bypass
description: A bypass of the GitPython safety guard allows arbitrary OS command execution via token smuggling when using single-character keyword arguments with split_single_char_options=False.
date: "2026-08-07T21:31:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - execution
  - library-vulnerability
  - command-injection
products:
  - GitPython (<= 3.1.57)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The guard's candidate list omits the smuggled option, but transform_kwarg emits a JOINED -n<value> argv token that git parses as --upload-pack=<cmd>, yielding arbitrary command execution
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-wvpp-8hx9-p66j
action_plan:
  priority: elevated
  owners:
    - Application Security
    - Development Teams
  immediate_actions:
    - action: Audit GitPython integration points for dynamic **kwargs passing
      owner: Development Teams
      due: 48h
      evidence: The vulnerability is triggered by forwarding user-controlled kwargs dictionaries
  mitigation_plan:
    - priority: immediate
      action: Upgrade GitPython to a patched version once available
      owner: IT Operations
      addresses: GitPython (<= 3.1.57)
      evidence: GitPython version 3.1.57 is explicitly listed as vulnerable
---

GitPython versions up to and including 3.1.57 contain a command injection vulnerability stemming from an incomplete fix for a previous guard bypass (GHSA-r9mr-m37c-5fr3). The library provides an `unsafe_git_clone_options` guard to prevent the passage of dangerous flags (e.g., `--upload-pack`) to the underlying git binary. An attacker who can control keyword arguments passed to GitPython methods (like `clone_from`, `fetch`, or `push`) can bypass this guard by setting `split_single_char_options=False` and providing a single-character key with a value containing a malicious command. 

The guard's candidate inspection logic fails to generate candidates for the joined tokens created when `split_single_char_options` is disabled. Consequently, the guard inspects the single-character key (e.g., '-n'), finds it safe, and passes. The subsequent `transform_kwarg` logic then assembles a joined token (e.g., `-nutouch <cmd>;git-upload-pack`) which the git binary parses as the `--upload-pack` flag. This results in the execution of the injected command with the privileges of the host process.

## Attack Chain

1. Attacker identifies an application endpoint that forwards user-controlled dictionaries as keyword arguments to a GitPython method (e.g., `Repo.clone_from(url, path, **kwargs)`).
2. Attacker provides a payload dict: `{'split_single_char_options': False, 'n': 'utouch /tmp/ACE;git-upload-pack'}`.
3. GitPython internal `_option_candidates` function processes the kwargs and identifies only `['-n']` as a candidate.
4. `check_unsafe_options` compares `['-n']` against the safety denylist.
5. The denylist check passes because `['-n']` is not considered an unsafe option, failing to see the smuggled command within the value.
6. The `transform_kwarg` function merges the key and value into a single CLI token: `-nutouch /tmp/ACE;git-upload-pack`.
7. The final argument list is passed to the underlying `git` subprocess.
8. Git parses the joined flag as `--upload-pack=utouch /tmp/ACE;git-upload-pack`, leading to arbitrary command execution.

## Impact

Successful exploitation allows for arbitrary OS command execution as the user running the GitPython process. This vulnerability affects any application utilizing GitPython's guarded methods while exposing kwargs to user input. The impact is significant as it facilitates unauthorized code execution and potential lateral movement or system compromise within environments hosting Git-integrated automation or CI/CD pipelines.

## Recommendation

Prioritize upgrading GitPython to a version where `_option_candidates` includes value-derived candidates regardless of `split_single_char_options`. If an immediate patch is unavailable, audit all code paths that forward user-supplied dictionaries as `**kwargs` to GitPython methods. Implement strict allowlisting for all keyword arguments instead of relying on the library's default guards. 
