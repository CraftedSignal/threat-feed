---
title: Arbitrary File Write in Dulwich via Malicious Git Tree Paths
slug: 2026-10-dulwich-path-traversal
description: The Dulwich Git library for Python fails to validate DOS drive letter prefixes on Windows, allowing a malicious Git repository to write files to arbitrary locations outside the designated worktree.
date: "2026-10-02T20:23:09Z"
lastmod: "2026-10-02T20:23:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - git
  - remote-code-execution
  - python
vendors:
  - Dulwich
products:
  - dulwich (< 1.2.9)
  - dulwich (>= 0.24.0, <= 1.2.7)
  - dulwich (>= 0.23.1, <= 1.2.7)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: An attacker can craft a malicious Git repository that, when cloned on a Windows machine, triggers the write of files to arbitrary locations outside the intended worktree.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This facilitates arbitrary file write, which can be leveraged for remote code execution by overwriting configuration files, startup items, or SSH keys.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Dropping a malicious executable into C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Writing to .git/hooks/post-checkout achieves RCE on the next git checkout.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-8mcx-5rqc-vhmf
  - https://github.com/advisories/GHSA-8w8g-wq8h-fq33
  - https://github.com/advisories/GHSA-5fqc-mrg8-w798
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade dulwich to version 1.2.9 or later
      owner: IT Operations
      due: 48h
      evidence: 'Source states: vulnerable < 1.2.9'
  mitigation_plan:
    - priority: immediate
      action: Upgrade dulwich to 1.2.9
      owner: IT Operations
      addresses: dulwich < 1.2.9
      evidence: Source identifies 1.2.9 as the fixed version
updates:
  - at: "2026-10-02T20:23:18Z"
    level: L2
    summary: added coverage for dulwich (>= 0.24.0, <= 1.2.7)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-8w8g-wq8h-fq33
  - at: "2026-10-02T20:23:25Z"
    level: L2
    summary: added coverage for dulwich (>= 0.23.1, <= 1.2.7)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-5fqc-mrg8-w798
---

Dulwich, a pure-Python implementation of the Git protocol, contains a critical path traversal vulnerability (versions < 1.2.9) when executing checkout operations on Windows. The library implements security checks in `validate_path_element_ntfs` and `_tree_to_fs_path` to block malicious path patterns like Alternate Data Streams (ADS) and reserved device names. However, these functions fail to identify or sanitize DOS drive letter prefixes (e.g., 'C:'). 

An attacker can craft a malicious Git repository containing a tree entry with a drive letter prefix. When a victim clones or checks out this repository on a Windows system, the library uses `os.path.join` incorrectly, causing the application to interpret the drive letter as an absolute path. This results in the target file being written to a location specified by the attacker, effectively discarding the intended worktree directory. This vulnerability provides a reliable primitive for Arbitrary File Write, which an attacker can weaponize to achieve Remote Code Execution (RCE) by targeting sensitive startup folders, user configuration files, or SSH keys.

## Attack Chain

1. Attacker crafts a malicious Git repository on a Linux system containing a tree structure with a directory named 'C:'.
2. Attacker populates the 'C:' directory with a malicious payload, such as a startup shortcut or a modified '.gitconfig' file.
3. Attacker pushes the repository to a public Git hosting platform or lures a victim to clone the repository.
4. Victim executes a `dulwich` clone or checkout command on a Windows machine.
5. Dulwich processes the malicious tree entry 'C:' and incorrectly joins it with the target worktree path.
6. Python's `os.path.join` on Windows recognizes the drive letter prefix and treats the path as absolute, bypassing the target directory constraint.
7. Dulwich writes the attacker-supplied payload to an arbitrary location on the victim's filesystem.
8. Upon file execution or system interaction with the malicious file, the attacker gains code execution or persistence on the victim's host.

## Impact

Successful exploitation results in arbitrary file write capabilities on Windows systems. This impact is severe for developers or CI/CD runners (e.g., GitHub Actions) using Dulwich, as it allows attackers to gain code execution by overwriting configuration files like `C:\Users\<user>\.gitconfig` or placing malicious binaries in `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\`. CI/CD pipelines are particularly vulnerable, as automated clones of malicious PRs can result in secret exfiltration and immediate host compromise.

## Recommendation

1. Upgrade the `dulwich` library to version 1.2.9 or later immediately to incorporate necessary path validation logic.
2. Implement monitoring for process creation events where `python.exe` or `git.exe` clones or checks out repositories to unconventional target paths on Windows.
3. Restrict write permissions on sensitive system directories such as the Windows Startup folder and user SSH directories to prevent unauthorized modifications by legitimate application processes.
4. Audit CI/CD runner environments for the presence of Dulwich and ensure runners are configured to use hardened Git clients or updated versions of the library.
