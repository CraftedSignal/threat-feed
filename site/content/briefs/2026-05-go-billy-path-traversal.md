---
title: go-billy Path Traversal Vulnerabilities
slug: 2026-05-go-billy-path-traversal
description: Multiple path traversal vulnerabilities exist in go-billy, particularly affecting the `osfs.ChrootOS` implementation, where crafted paths can escape intended base directories due to insufficient path sanitization and boundary enforcement; users requiring stronger security should upgrade to v6 and use `os.Root`.
date: "2026-05-14T18:27:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - go-billy
  - CVE-2026-44973
vendors:
  - go-git
products:
  - go-billy/v5
  - go-billy/v6
affected_os:
  - linux
  - windows
  - macos
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-qw64-3x98-g7q2
  - https://go.dev/blog/osroot
  - https://pkg.go.dev/os#Root
rules:
  - title: Detect CVE-2026-44973 Exploitation Attempt - Path Traversal in go-billy
    description: Detects potential exploitation attempts of CVE-2026-44973, path traversal vulnerabilities in go-billy, by monitoring process creations with suspicious file paths containing multiple '..' sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
  - title: Detect CVE-2026-44973 Exploitation Attempt - File Access with Path Traversal
    description: Detects potential exploitation attempts of CVE-2026-44973, path traversal vulnerabilities in go-billy, by monitoring file events with suspicious file paths containing multiple '..' sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The `go-billy` library has multiple path traversal vulnerabilities due to insufficient path sanitization and boundary enforcement. Crafted paths, particularly using `..`, can escape the intended base directories. The `osfs.ChrootOS` implementation is affected and has been deprecated in `v5` and removed in `v6`. Applications relying on `go-billy` for some level of isolation may inadvertently expose access to unintended filesystem locations. Users requiring stronger security boundary enforcement are advised to upgrade to `v6`, where the `osfs` implementation is backed by the traversal-resistant primitive `os.Root`. Versions prior to `v5` are likely affected; upgrading to a supported version is recommended. The vulnerability is identified as CVE-2026-44973.

## Attack Chain

1. An attacker crafts a malicious path using directory traversal sequences (e.g., `../`) designed to escape the intended file system boundaries.
2. The application using `go-billy` receives the crafted path, intending to access a file within a restricted directory.
3. The application calls `go-billy` functions (e.g., `Open`, `ReadFile`, `Stat`) to interact with the file system using the attacker-controlled path.
4. Due to insufficient sanitization within the vulnerable `osfs.ChrootOS` implementation, the traversal sequences are not properly resolved or blocked.
5. `go-billy`'s file system access functions resolve the path, allowing the attacker to navigate outside the intended directory and access sensitive files or directories.
6. The application reads or modifies files outside the intended scope, leading to potential information disclosure or arbitrary file manipulation.
7. The attacker gains unauthorized access to sensitive data or system resources.
8. The attacker may further exploit the compromised system to achieve lateral movement or other malicious objectives.

## Impact

Successful exploitation of these path traversal vulnerabilities can lead to unauthorized access to sensitive files and directories, potentially resulting in information disclosure or arbitrary file manipulation. The number of victims and targeted sectors depend on the specific applications using the vulnerable `go-billy` library. If the attack succeeds, attackers can bypass intended security boundaries, read configuration files, or even modify critical system files, leading to complete system compromise.

## Recommendation

*   Upgrade to `go-billy` version 6 or later to leverage the more secure `os.Root` implementation for `osfs` to prevent CVE-2026-44973.
*   Migrate away from `osfs.ChrootOS` and use `osfs.BoundOS` instead, as `osfs.ChrootOS` is deprecated and vulnerable as noted in the overview.
*   Enable process creation logging on affected systems to facilitate detection of suspicious file access patterns.
