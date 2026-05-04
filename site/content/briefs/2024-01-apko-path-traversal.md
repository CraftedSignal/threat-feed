---
title: Apko DirFS Symlink Path Traversal Vulnerability
slug: 2024-01-apko-path-traversal
description: A symlink-following path traversal vulnerability exists in apko versions prior to 1.2.5 allowing a malicious .apk file to create a symbolic link pointing outside the build root and subsequently modify files on the host system.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - symlink
  - apko
  - vulnerability
  - CVE-2026-42574
vendors:
  - Chainguard
products:
  - apko (< 1.2.5)
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1553
    technique_name: Subvert Trust Relationships
references:
  - https://github.com/advisories/GHSA-qq3r-w4hj-gjp6
  - https://github.com/chainguard-dev/apko/pull/2187
  - https://github.com/chainguard-dev/apko/commit/f5a96e1299ac81c7ea9441705ec467688086f442
  - https://github.com/chainguard-dev/apko/releases/tag/v1.2.5
rules:
  - title: Detect suspicious file creation outside build root (simulated)
    description: 'Detects file creation events in sensitive directories that might indicate path traversal exploitation. Note: This is a simulated detection as actual directory paths depend on the build environment.'
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1553.005
    data_sources:
      - file_event
      - linux
  - title: Detect apko build-cpio execution
    description: Detects execution of the apko build-cpio command, which is a component of the attack chain.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1553.005
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A path traversal vulnerability exists in apko's `DirFS` component, specifically within the `sanitizePath` helper function in versions prior to 1.2.5. The vulnerability allows a malicious `.apk` file to install a `TypeSymlink` tar entry pointing outside the intended build root. Subsequent directory creation or file writing operations could then traverse this symbolic link, leading to unauthorized access and modification of files on the host system. This issue affects users of apko and downstream tools, such as melange, that embed vulnerable versions of the `pkg/apk/fs` package. The vulnerability was addressed in apko version 1.2.5 with the introduction of `*os.Root`, which prevents path traversal.

## Attack Chain

1.  An attacker crafts a malicious `.apk` file containing a `TypeSymlink` tar entry.
2.  The symbolic link's target is set to a path outside the intended build root, potentially targeting sensitive system directories.
3.  The malicious `.apk` is processed using a vulnerable version of apko (prior to 1.2.5) via commands like `apko build-cpio` or through disk-backed consumers such as `melange`.
4.  During tar extraction, the vulnerable `sanitizePath` function fails to properly resolve or refuse the malicious symlink.
5.  A subsequent directory-creation or file-write operation is initiated within the same or a later archive entry.
6.  The file operation traverses the previously created symbolic link, gaining access to the file system location outside the intended build root.
7.  The attacker can then create directories or write files to the compromised location, potentially overwriting critical system files or injecting malicious code.
8.  Successful exploitation can lead to privilege escalation and persistent compromise of the host system.

## Impact

Successful exploitation of this vulnerability allows an attacker to write files to arbitrary locations on the host system. This can lead to privilege escalation if the attacker can overwrite setuid binaries or modify system configuration files. It can also lead to persistent compromise of the system if the attacker injects malicious code into startup scripts or other system files. While the exact number of victims is unknown, any system running a vulnerable version of apko (prior to 1.2.5) or tools embedding vulnerable versions of `pkg/apk/fs`, such as melange, is potentially at risk.

## Recommendation

*   Upgrade apko to version 1.2.5 or later. This version includes a fix that prevents path traversal vulnerabilities as described in the advisory and commit [f5a96e1](https://github.com/chainguard-dev/apko/commit/f5a96e1299ac81c7ea9441705ec467688086f442).
*   If upgrading is not immediately feasible, avoid consuming APKs from untrusted sources. However, note that this does not fully eliminate the risk.
*   Monitor file creation events in sensitive directories for unexpected activity, especially after processing `.apk` files.
