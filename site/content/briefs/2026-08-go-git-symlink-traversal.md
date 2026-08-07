---
title: Symlink Traversal Vulnerability in go-git
slug: 2026-08-go-git-symlink-traversal
description: A symlink traversal vulnerability in the go-git library (CVE-2026-71556) enables unauthorized write access outside of the intended worktree directory when processing malicious symbolic links.
date: "2026-08-07T21:31:15Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - go-git
products:
  - go-git v5
  - go-git v6
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: An attacker could manipulate file system operations to modify repository metadata or configurations by crafting symbolic links that the library follows.
    confidence_band: med
cves:
  - id: CVE-2026-71556
    cvss: 7.1
references:
  - https://github.com/advisories/GHSA-hc8v-wwc9-vgxm
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71556
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory applications using go-git and update to patched versions
      owner: Security Engineering
      due: 72h
      evidence: Source notes patched versions exist
---

The go-git library is susceptible to a symlink traversal vulnerability (CVE-2026-71556) affecting versions v5.19.1 and earlier, as well as v6.0.0-alpha.4 and earlier. The vulnerability exists within the worktree filesystem wrapper, which failed to correctly sanitize symbolic links during file operations. While the library previously implemented checks against path strings containing parent-directory components or control characters, it did not account for symbolic links already present in the worktree. An attacker who can influence the content of a Git repository or directory being processed can introduce a symbolic link that points to sensitive locations, such as the .git metadata directory. When the library performs file operations through this path, it follows the symlink, resulting in an escape from the intended directory. This could lead to the modification or truncation of sensitive repository configuration files. Applications that rely on memory-based storage or go-billy/memfs are not affected.

## Impact

Successful exploitation allows for out-of-bounds file writes, potentially enabling an attacker to corrupt repository metadata, modify git configurations, or cause denial-of-service by overwriting essential files. This issue poses a significant risk to CI/CD pipelines, build systems, and development environments that process untrusted repositories using vulnerable versions of go-git.

## Recommendation

- Upgrade go-git to a patched version that implements a symlink-safe boundary for filesystem operations.
- Review applications currently utilizing filesystem-backed worktrees for processing untrusted git repositories.
- Prioritize migration to memory-based storage for sensitive operations where the performance or persistence requirements permit.
