---
title: Arbitrary File Write in Dulwich via Symlink Directory Traversal
slug: 2026-10-dulwich-stash-traversal
description: The Dulwich library stash pop implementation fails to validate symlinks, allowing attackers to write arbitrary files outside the repository worktree and achieve remote code execution.
date: "2026-10-02T20:23:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary-file-write
  - path-traversal
  - execution
products:
  - dulwich (0.22.5 - 1.2.7)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: By overwriting sensitive files such as .git/hooks/post-checkout, an attacker can achieve remote code execution when the victim performs subsequent git operations.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-cm62-gvxx-vmxx
action_plan:
  priority: elevated
  owners:
    - Security Operations
    - Engineering
  immediate_actions:
    - action: Inventory all internal services and development workstations using the Dulwich library
      owner: Engineering
      due: 48h
      evidence: Dulwich versions 0.22.5 through 1.2.7 are affected by this high-severity vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade or patch Dulwich in all affected environments
      owner: Engineering
      addresses: dulwich library vulnerability
      evidence: Source advises updating to a patched version when available.
---

The Dulwich library contains a path traversal vulnerability in its `stash.pop()` function, specifically within `dulwich/stash.py`. The vulnerability arises because the library uses `os.path.exists()` to verify directory paths before writing stashed files. Because `os.path.exists()` follows symlinks, it fails to detect when a target path resolves to a location outside the repository worktree. The `validate_path()` function provides insufficient validation as it only checks against forbidden filenames and does not account for symlink resolution. This flaw affects Dulwich versions 0.22.5 through 1.2.7. An attacker can weaponize this by creating a repository with carefully crafted symlinks that, when popped by a victim, overwrite sensitive system files or local configuration files.

## Attack Chain

1. Attacker creates a malicious git repository containing a symlink (e.g., `link` pointing to `../../.git/hooks`).
2. Attacker creates a stash containing an executable payload file nested within that symlinked path (e.g., `link/post-checkout`).
3. Victim clones the malicious repository and checks out the branch containing the symlink.
4. Victim executes `stash.pop()` on the malicious stash content.
5. Dulwich evaluates the target path, where `os.path.exists()` confirms the presence of the directory via the symlink, bypassing safety checks.
6. The `build_file_from_blob()` function writes the payload content directly to the resolved location.
7. The payload is written to the victim's local `.git/hooks/post-checkout` file.
8. The victim triggers the payload upon the next git checkout, resulting in Remote Code Execution.

## Impact

Successful exploitation allows for arbitrary file writes on the victim's system. By targeting critical hooks like `.git/hooks/post-checkout` within the local environment, an attacker can gain arbitrary command execution under the user context of the victim, leading to full compromise of the local development workstation.

## Recommendation

1. Update the Dulwich library to a patched version once available.
2. Audit all automated tooling that utilizes Dulwich for git repository management to ensure they are running with the least privilege necessary.
3. Monitor local development directories for unexpected creation or modification of git hook files using File Integrity Monitoring (FIM).
4. For developers using the Dulwich library, implement path canonicalization using `os.path.realpath()` before file write operations to verify the target directory resides within the expected worktree.
