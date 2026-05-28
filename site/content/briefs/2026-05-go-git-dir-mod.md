---
title: CVE-2026-45571 go-git Crafted Repositories Modify .git Directories
slug: 2026-05-go-git-dir-mod
description: CVE-2026-45571 is a vulnerability in go-git that allows crafted repositories to modify main and submodule .git directories, potentially leading to arbitrary code execution or information disclosure.
date: "2026-05-28T07:25:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - go-git
  - git
  - directory modification
  - code execution
products:
  - go-git
cves:
  - id: CVE-2026-45571
    cvss: 5.4
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45571
rules:
  - title: Detect Go-Git .git Directory Modification
    description: Detects CVE-2026-45571 exploitation -- attempts to modify .git directories which can lead to code execution via git hooks
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Git Hook Creation in .git Directory
    description: Detects CVE-2026-45571 exploitation -- creation of new executable files inside .git/hooks directory which could indicate the injection of malicious git hooks
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-45571 is a critical vulnerability affecting the go-git library, a popular Go implementation of Git. This flaw allows a malicious actor to craft a Git repository that, when processed by a vulnerable application using go-git, can modify the `.git` directories of both the main repository and its submodules. This modification could be leveraged to overwrite configuration files, inject malicious Git hooks, or otherwise compromise the integrity of the repository and the system on which it resides. Successful exploitation could lead to arbitrary code execution or sensitive information disclosure. Defenders should prioritize identifying and mitigating applications utilizing vulnerable versions of go-git.

## Attack Chain

1.  An attacker crafts a malicious Git repository containing specially crafted files or symbolic links designed to manipulate `.git` directories.
2.  A user or automated system clones or interacts with the malicious repository using a vulnerable version of go-git.
3.  The vulnerable go-git library processes the malicious repository content without proper validation or sanitization.
4.  The crafted content overwrites or modifies configuration files within the main repository's `.git` directory.
5.  The crafted content also propagates to any submodules present, modifying their respective `.git` directories.
6.  The modification of `.git` directories allows the attacker to inject malicious Git hooks (e.g., pre-commit, post-receive).
7.  When a user performs Git operations (e.g., commit, push, pull), the injected malicious hooks are executed.
8.  The malicious hooks execute arbitrary code, potentially leading to complete system compromise or data exfiltration.

## Impact

Successful exploitation of CVE-2026-45571 can have severe consequences. An attacker could gain arbitrary code execution on systems using vulnerable versions of go-git. This could lead to data breaches, system compromise, and denial-of-service attacks. The vulnerability poses a significant risk to organizations that rely on go-git for managing source code, configuration files, or other sensitive data within Git repositories. The lack of specific victim count data makes assessing the total impact difficult, but the wide usage of go-git implies a potentially broad attack surface.

## Recommendation

*   Upgrade go-git to a patched version that addresses CVE-2026-45571.
*   Implement the Sigma rule "Detect Go-Git .git Directory Modification" to detect potential exploitation attempts in real-time.
*   Review and audit existing Git repositories for suspicious files or symbolic links that could be used to exploit this vulnerability.
*   Monitor file system events within `.git` directories using the Sigma rule "Detect Git Hook Creation in .git Directory" to identify unauthorized modifications.
