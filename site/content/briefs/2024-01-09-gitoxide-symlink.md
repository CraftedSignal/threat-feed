---
title: gix and gitoxide Repository Boundary Violation via Symlinked .gitmodules
slug: 2024-01-09-gitoxide-symlink
description: A vulnerability in gix and gitoxide allows a malicious repository to use a symlinked `.gitmodules` file pointing outside the repository, leading to the parsing of arbitrary, attacker-controlled submodule configurations and potential manipulation of downstream git operations.
date: "2026-05-05T19:26:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - symlink
  - gitoxide
  - gix
  - repository-boundary-violation
vendors:
  - GitoxideLabs
products:
  - gitoxide (<= 0.52.0)
  - gix (< 0.83.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/advisories/GHSA-pg4w-g64p-qwhj
iocs:
  - type: url
    value: https://attacker.example/symlinked.git
ioc_counts:
  url: 1
rules:
  - title: Detect gitoxide/gix Submodule URL from External Domain
    description: Detects processes that may be using gitoxide or gix to access submodule URLs from suspicious or external domains, indicating a potential repository boundary violation. Requires process creation logs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Detect gitoxide/gix Accessing .gitmodules via Symlink
    description: This rule detects potential exploitation of the gitoxide/gix symlink vulnerability by monitoring file access events for `.gitmodules` where the file path contains a symbolic link.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A repository boundary violation vulnerability exists in gitoxide (<= 0.52.0) and gix (< 0.83.0) related to how submodule metadata is loaded. When `Repository::submodules()` is called, the library prefers the worktree's `.gitmodules` file. The vulnerability arises because the library uses `std::fs::read()` to read this file, which follows symbolic links. A malicious repository can exploit this by including a symlinked `.gitmodules` file that points to an external location. As a result, gitoxide parses submodule configurations from an attacker-controlled file outside the repository, leading to potential injection of malicious metadata. This can mislead callers about submodule metadata, such as name, path, and URL, and influence downstream workflows related to cloning, fetching, or updating.

## Attack Chain

1.  Attacker creates a malicious repository.
2.  The repository contains a symbolic link named `.gitmodules` that points to a file outside the repository's worktree controlled by the attacker.
3.  A user clones the malicious repository using a vulnerable version of gitoxide or gix.
4.  The application calls `Repository::submodules()` to enumerate submodules.
5.  `std::fs::read()` follows the symlink when reading the `.gitmodules` file.
6.  gitoxide parses the contents of the attacker-controlled file as submodule configuration.
7.  The parsed submodule data, including attacker-controlled name, path, and URL values, is exposed through the `Submodule` objects.
8.  Downstream git workflows use the injected metadata to clone, fetch, update, or enforce policies, potentially leading to unintended or malicious actions.

## Impact

The vulnerability allows for the injection of out-of-repository bytes into the result of `Repository::submodules()`. This means attackers can mislead callers about submodule metadata, such as name, path, and URL. Any downstream workflow that uses these values to decide clone, fetch, update, or policy behavior is operating on attacker-controlled data. While the report doesn't claim direct command execution, it highlights the risk of metadata injection across the repository boundary, potentially leading to security breaches or data compromise.

## Recommendation

Prioritize the following actions to mitigate this vulnerability:

*   Upgrade to gitoxide version > 0.52.0 or gix version >= 0.83.0 to incorporate the fix that prevents following symlinks for `.gitmodules` (Affected Products).
*   Implement checks to reject symlinked `.gitmodules` files when loading from the worktree using `symlink_metadata()` or `lstat` style checks (Reference: GHSA-pg4w-g64p-qwhj).
*   Canonicalize the target path of `.gitmodules` and verify that it resides within the repository worktree before reading (Reference: GHSA-pg4w-g64p-qwhj).
*   For security-sensitive callers, prefer loading `.gitmodules` from the index or `HEAD` tree rather than following the worktree path (Reference: GHSA-pg4w-g64p-qwhj).
