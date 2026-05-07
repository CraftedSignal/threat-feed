---
title: gix-fs Symlink Prefix-Reuse Worktree Escape
slug: 2024-01-30-gix-symlink-escape
description: A vulnerability in rust's gix-fs library (<= 0.21.0) allows a malicious actor to construct a tree that, when checked out with gitoxide, permits writing an attacker-controlled symlink into any existing directory the user has write access to, potentially leading to code execution.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - symlink
  - worktree-escape
  - gitoxide
  - gix-fs
  - code-execution
vendors:
  - rust
products:
  - gix-fs (<= 0.21.0)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1559
    technique_name: Hooking
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1559
    technique_name: Hooking
references:
  - https://github.com/advisories/GHSA-f89h-2fjh-2r9q
rules:
  - title: Detect Git Symlink Creation in .git/hooks
    description: Detects the creation of symlinks within the .git/hooks directory, which could indicate exploitation of the gix-fs vulnerability.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1559.002
    data_sources:
      - file_event
      - linux
  - title: Detect Git Symlink Creation in .git/hooks Windows
    description: Detects the creation of symlinks within the .git/hooks directory, which could indicate exploitation of the gix-fs vulnerability.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1559.002
    data_sources:
      - file_event
      - windows
  - title: Detect Gitoxide Process Executing
    description: Detects the execution of gitoxide, which may be used to exploit the gix-fs vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1559
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

A critical vulnerability exists in the rust's gix-fs library, specifically in versions 0.21.0 and earlier. This flaw allows a malicious actor to craft a Git tree in such a way that, when checked out using gitoxide, an attacker-controlled symlink can be written into any directory on the file system where the user possesses write permissions. The vulnerability arises from the reuse of validated path prefixes during the checkout process, specifically when handling symlinks. Project Glasswing discovered this flaw, identified as CVE-2026-44471, which has the potential for privilege escalation and arbitrary code execution. The issue stems from how gix-fs handles symlinks during the checkout process, allowing malicious actors to bypass security checks.

## Attack Chain

1. An attacker crafts a malicious Git tree containing a symlink entry ('a') pointing to a sensitive directory (e.g., '.git/hooks').
2. The attacker creates a directory entry ('a') within the same tree, including a subtree with a symlink (e.g., 'post-checkout') pointing to a payload file ('../../payload').
3. The crafted Git tree is processed by `gix_index::State::from_tree()`, which converts it into index entries (e.g., ["a" (SYMLINK), "a/post-checkout" (SYMLINK)]).
4. During the delayed symlink phase of the checkout process, the symlink 'a' is created, linking to the target directory (e.g., '.git/hooks').
5. When processing 'a/post-checkout', the validated prefix 'a' is reused, bypassing intermediate directory checks.
6. The `symlink()` function resolves through the previously created symlink ('a'), leading to the creation of a symlink at the attacker-controlled location (e.g., '.git/hooks/post-checkout').
7. The attacker places an executable payload file ('payload') in the repository.
8. Upon triggering the 'post-checkout' hook (e.g., via `git checkout -b new-branch`), the payload is executed, resulting in arbitrary code execution.

## Impact

Successful exploitation of this vulnerability allows an attacker to create arbitrary symlinks in any directory the user has write access to. This can lead to arbitrary code execution, privilege escalation, and potential system compromise. By writing to sensitive locations like `.git/hooks`, attackers can establish persistence and execute malicious code whenever Git commands are run. The impact is significant, as it allows attackers to bypass standard security checks and gain unauthorized access to the system.

## Recommendation

*   Upgrade to a patched version of the `gix-fs` library that addresses CVE-2026-44471 to prevent exploitation of the symlink vulnerability.
*   Monitor process creation events for git processes creating symlinks in sensitive directories such as .git/hooks, using a detection rule focused on suspicious symlink creation.
*   Implement strict file integrity monitoring on critical system directories to detect unauthorized modifications, especially within `.git` directories.
