---
title: BuildKit Git URL Subdir Traversal Vulnerability
slug: 2024-01-buildkit-git-url-vuln
description: A vulnerability in BuildKit (fixed in v0.28.1) allows for potential file access outside the Git repository root due to insufficient validation of Git URL fragment subdirectories, potentially leading to privilege escalation.
date: "2024-01-25T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buildkit
  - git
  - directory-traversal
  - privilege-escalation
vendors:
  - Docker
products:
  - BuildKit
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-4vrq-3vrq-g6gg
  - https://docs.docker.com/build/concepts/context/#url-fragments
rules:
  - title: Detect BuildKit File Access Outside Git Repo
    description: Detects BuildKit accessing files outside of a git repository during a build process, indicating potential directory traversal.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious Git URL in Dockerfile
    description: Detects the use of a Git URL with a subpath in a Dockerfile, which could be indicative of an attempt to exploit CVE-2026-33748.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A vulnerability exists in BuildKit, a toolkit for converting source code to build artifacts, specifically in how it handles Git URLs with subpath components. This flaw, identified as CVE-2026-33748, stems from insufficient validation of the subdir component within Git URLs (e.g., `<url>#<ref>:<subdir>`).  An attacker can exploit this by crafting a malicious Git repository with a carefully constructed subpath that points to a symbolic link or other mechanism to access files outside of the intended Git repository root. This could lead to unauthorized access to sensitive files within the same mounted filesystem. The vulnerability affects BuildKit versions prior to v0.28.1. Defenders should prioritize updating BuildKit installations and carefully scrutinize the sources of Dockerfiles used in their build processes.

## Attack Chain

1.  Attacker creates a malicious Git repository containing a symbolic link within the repository.
2.  The symbolic link is crafted to point outside the repository root to a sensitive file or directory on the same filesystem.
3.  The attacker crafts a Dockerfile that uses a Git URL with a subpath component, pointing to the malicious repository and specifying the symbolic link as the subdirectory.
4.  A BuildKit build process is initiated, using the attacker-controlled Dockerfile.
5.  BuildKit fetches the Git repository.
6.  Due to insufficient validation, BuildKit follows the symbolic link specified in the subpath.
7.  BuildKit accesses the file or directory outside the Git repository root, as targeted by the symbolic link.
8.  The attacker gains unauthorized access to sensitive files or configurations, potentially leading to privilege escalation within the build environment.

## Impact

Successful exploitation of CVE-2026-33748 can allow attackers to read arbitrary files within the same filesystem as the BuildKit process, potentially exposing sensitive information like credentials, configuration files, or source code. While the scope is limited to the same mounted filesystem, this can still provide a significant stepping stone for further attacks. The number of affected systems is potentially large, as BuildKit is a widely used component in container build processes.

## Recommendation

*   Upgrade BuildKit installations to version v0.28.1 or later to patch CVE-2026-33748.
*   Implement checks to validate the source of Dockerfiles and Git repositories used in build processes. Specifically, review Git URLs for unexpected or suspicious subpath components.
*   Monitor process creation events for `buildkitd` processes accessing files outside the expected Git repository directories. Use the provided Sigma rule to detect suspicious file access.
*   Where possible, avoid using Git URLs with subpath components from untrusted sources, as recommended in the advisory.
