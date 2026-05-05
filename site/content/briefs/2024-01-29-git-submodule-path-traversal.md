---
title: gix and gitoxide Submodule Path Traversal Vulnerability
slug: 2024-01-29-git-submodule-path-traversal
description: A path traversal vulnerability exists in gix and gitoxide where unvalidated submodule names from `.gitmodules` can be used to escape the `.git/modules` directory, potentially leading to repository confusion by redirecting submodule state inspection and open operations to attacker-controlled paths.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - git
  - repository-confusion
  - supply-chain
vendors:
  - GitoxideLabs
products:
  - gix
  - gitoxide
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
references:
  - https://github.com/advisories/GHSA-fr8x-3vfx-f45h
rules:
  - title: Detect Git Submodule Path Traversal in Configuration
    description: Detects potentially malicious `.gitmodules` files containing submodule names with path traversal sequences (e.g., '../../../escaped-target.git'). This may indicate an attempt to exploit the gix/gitoxide path traversal vulnerability.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - file_event
      - linux
  - title: Detect gix or gitoxide process accessing suspicious paths
    description: Detects gix or gitoxide processes accessing paths outside of the .git/modules directory. This may indicate an attempt to exploit the path traversal vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A path traversal vulnerability has been identified in the gix and gitoxide libraries. The vulnerability stems from the lack of validation of submodule names extracted from the `.gitmodules` file. Specifically, these submodule names are used to construct file paths for accessing submodule Git directories. An attacker can craft a malicious `.gitmodules` file containing a submodule name with path traversal sequences (e.g., `../../../escaped-target.git`). This allows the attacker to redirect `state()` and `open()` calls to an arbitrary repository outside the intended `.git/modules` directory. This can cause a vulnerable application using these libraries to operate on an unexpected repository, leading to potential security issues. The vulnerability affects gix versions prior to 0.83.0 and gitoxide versions up to and including 0.52.0.

## Attack Chain

1. An attacker crafts a malicious `.gitmodules` file.
2. The malicious `.gitmodules` file contains a submodule name with path traversal sequences (e.g., `../../../escaped-target.git`).
3. A vulnerable application using gix or gitoxide parses the malicious `.gitmodules` file.
4. The application extracts the unvalidated submodule name from the `.gitmodules` file.
5. The application constructs a file path to the submodule's Git directory using the unvalidated name: `<superproject common_dir>/modules/<submodule name>`.
6. Due to the path traversal sequences in the submodule name, the constructed path escapes the intended `.git/modules` directory.
7. The application calls `state()` or `open()` using the escaped path, which leads to an attacker-controlled repository.
8. The application performs operations (enumeration, inspection, etc.) on the attacker-chosen repository, potentially leading to information disclosure or other unexpected behavior.

## Impact

The vulnerability can lead to repository confusion, where a vulnerable application operates on an unintended repository. While the report does not claim direct command execution, the redirection of repository access can have significant consequences. For example, if the application relies on submodule state for access control or other security-sensitive operations, an attacker could potentially bypass these checks by redirecting the application to a controlled repository. The number of victims and sectors affected depend on the adoption of the vulnerable gix and gitoxide libraries.

## Recommendation

- Upgrade to gix version 0.83.0 or later to patch the vulnerability.
- Upgrade to a version of gitoxide later than 0.52.0, if available (or switch to gix).
- Deploy the Sigma rule `Detect Git Submodule Path Traversal in Configuration` to identify potentially malicious `.gitmodules` files based on submodule name patterns.
- Sanitize or validate submodule names before using them to construct file paths, as recommended in the advisory.
- Monitor application logs for suspicious activity related to submodule operations, especially those involving unusual file paths.
