---
brief_id: brief-2026-10-29-gitpython-rce-8a12154e
event_id: brief-2026-10-29-gitpython-rce-8a12154e
revision: 1
activity_at: "2026-10-29T23:25:26Z"
title: 'GitPython: Remote.pull() arbitrary command execution via refspec injection'
slug: 2026-10-gitpython-rce-8a12154e
description: The GitPython library fails to validate the refspec positional argument in Remote.pull(), allowing attackers to inject shell commands via --upload-pack options when using SSH or local transports.
date: "2026-10-29T23:25:26Z"
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
  validation_status: Verified against source documentation
tags:
  - remote-code-execution
  - gitpython
  - library-vulnerability
vendors:
  - GitPython
products:
  - GitPython (>= 3.1.30, < 3.2.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
    evidence: An attacker who controls the refspec value passed to Remote.pull() achieves arbitrary operating-system command execution as the process invoking GitPython.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-f9j4-qggq-h239
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - Application Security
  immediate_actions:
    - action: Inventory applications using GitPython to pull from SSH or local filesystem origins.
      owner: Application Security
      due: 48h
      evidence: Exploitation requires that the pulled remote uses a transport that runs upload-pack on the local side.
  hunt_leads:
    - lead: Search process logs for 'git pull' or 'git fetch' commands containing '--upload-pack=' in the command-line arguments.
      technique_id: T1059
      data_needed:
        - Process creation logs (CommandLine)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker supplies the string --upload-pack=<command>; git-upload-pack.
  mitigation_plan:
    - priority: medium
      action: Implement strict allow-listing for refspec parameters in web or CI services interacting with GitPython.
      owner: Application Security
      addresses: GitPython (>= 3.1.30, < 3.2.0)
      evidence: Callers should validate or reject refspec values that begin with -.
---

GitPython's `Remote.pull()` method contains a vulnerability in its security guard intended to prevent command injection. While the library attempts to block dangerous options like `--upload-pack`, the guard only inspects keyword arguments and fails to validate the positional `refspec` argument. An attacker can supply a refspec starting with `--upload-pack=`, which is forwarded to the underlying `git pull` process. Because `git pull` does not properly terminate positional arguments before passing them to internal `git fetch` operations, the injected command is executed as the `upload-pack` program. Exploitation is possible when using local filesystem or SSH transports. No fix is currently available.

## Attack Chain

1. Exposure: An application calls `Remote.pull(refspec=<value>)` where `<value>` is derived from attacker-influenced input.
2. Control: The attacker provides a string such as `--upload-pack=<command>; git-upload-pack`.
3. Path: The input passes through `Git._unpack_args` and `Git.check_unsafe_protocols` without being flagged as malicious.
4. Guard: The unsafe-option guard incorrectly assumes positionals are safe, failing to check the `refspec` against `unsafe_git_pull_options`.
5. Primitive: The `refspec` is passed to `git pull -v -- <remote> <refspec>`.
6. Execution: The `git pull` command forwards the positional to an internal `git fetch` without a `--` separator, causing the system to execute the injected command as the `upload-pack` program.
7. Result: Arbitrary command execution occurs on the system with the privileges of the calling process.

## Impact

Successful exploitation allows arbitrary command execution as the user running the GitPython process. This requires the use of SSH or local filesystem transports; HTTPS transports are not affected as the server ignores the client-supplied upload-pack program.

## Recommendation

- Validate that all `refspec` strings passed to `Remote.pull()` do not start with a hyphen (`-`).
- Prefer HTTPS remotes over local-path or SSH transports where possible.
- Avoid passing untrusted user input directly into GitPython method arguments.
- Monitor for GitPython processes spawning child processes that are not standard git utilities or that originate from unexpected command-line arguments.
