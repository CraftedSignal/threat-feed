---
title: gix Submodule Path Traversal and Credential Disclosure
slug: 2024-01-03-gix-submodule-traversal
description: A vulnerability in gix's submodule name validation allows path traversal via a crafted .gitmodules file, combined with a trust inheritance flaw in Submodule::open(), enabling arbitrary git repository config reading, including credentials, with full trust.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - credential-disclosure
  - git
vendors:
  - rust
products:
  - 'gix (vulnerable: < 0.83.0)'
  - 'gix-validate (vulnerable: <= 0.10.0)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Files
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-p3hw-mv63-rf9w
rules:
  - title: Detect Git Submodule Path Traversal
    description: Detects command line arguments indicative of path traversal attempts within git submodule operations.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
  - title: Suspicious gix process with Trust::Full
    description: Detects processes using the gix library that might inherit Trust::Full, indicating a potential trust bypass vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A path traversal vulnerability exists within the gix library, specifically affecting applications that utilize git submodules. This flaw stems from inadequate validation of submodule names, allowing an attacker to craft a malicious `.gitmodules` file containing directory traversal sequences (e.g., `../`). The vulnerability is amplified by a trust inheritance issue where submodule repositories inherit the `git_dir_trust` setting from their parent, bypassing ownership checks. Successful exploitation allows an attacker to read sensitive configuration files, potentially including credentials, from arbitrary git directories. This vulnerability affects gix versions prior to 0.83.0 and gix-validate versions 0.10.0 and earlier.

## Attack Chain

1. An attacker crafts a malicious git repository with a specially crafted `.gitmodules` file containing path traversal sequences in the submodule name (e.g., `x..y/../../..`).
2. A victim clones the attacker's repository using a tool built on the vulnerable gitoxide library (gix).
3. The victim's tool iterates through the submodules, potentially triggered by commands like `submodule.open()` or `submodule.status()`.
4. The `git_dir()` function, due to insufficient validation, constructs a path that traverses outside the intended submodule directory (e.g., resolving to the parent `.git/` directory).
5. The `open_opts()` function is called with `Trust::Full` inherited from the parent repository, skipping ownership checks.
6. The library opens the traversed path (e.g., the parent's `.git/config` file) as a trusted repository.
7. The attacker can then access sensitive configuration values, such as `remote.origin.url`, `http.extraHeader` (containing tokens), `credential.*` sections, and `core.sshCommand`.
8. The attacker extracts the exposed credentials via standard API calls, such as `repo.config_snapshot().string("http.extraHeader")`.

## Impact

Successful exploitation of this vulnerability enables an attacker to read sensitive configuration files from arbitrary git repositories accessible to the vulnerable application. This includes potential disclosure of credentials such as tokens embedded in URLs or HTTP headers, SSH keys, and other sensitive information. The impact is high due to the potential for lateral movement and further compromise within the victim's environment. This is similar to GHSA-7w47-3wg8-547c.

## Recommendation

*   Apply the suggested fix by patching the gix and gix-validate libraries to version 0.83.0 or later to resolve the validation bypass and trust inheritance issues.
*   Implement a detection rule for process creation events where a git command is executed with a submodule path containing directory traversal sequences (`..`) based on the flawed validation in `gix-validate/src/submodule.rs` as described in the overview.
*   Deploy the Sigma rule "Detect Git Submodule Path Traversal" to identify potential exploitation attempts (see rules section below).
