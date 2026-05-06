---
title: GitPython Path Traversal Vulnerability Allows Arbitrary File Manipulation
slug: 2024-01-gitpython-path-traversal
description: A path traversal vulnerability in GitPython allows attackers who can supply a crafted reference path to an application using GitPython to write, overwrite, move, or delete files outside the repository’s .git directory via insufficient validation of reference paths in reference creation, rename, and delete operations.
date: "2024-01-08T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - file-manipulation
  - gitpython
vendors:
  - pip
products:
  - GitPython (<= 3.1.47)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-7545-fcxq-7j24
rules:
  - title: Detect GitPython Path Traversal File Creation
    description: Detects attempts to create files outside the repository directory using GitPython, indicative of a path traversal attack.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect GitPython Path Traversal File Deletion
    description: Detects attempts to delete files outside the repository directory using GitPython, indicative of a path traversal attack.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect GitPython Path Traversal File Rename
    description: Detects attempts to rename files to a location outside the repository directory using GitPython, indicative of a path traversal attack.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

A path traversal vulnerability exists in GitPython versions 3.1.46 and earlier. This vulnerability allows an attacker who can control the reference path supplied to a GitPython application to perform arbitrary file system operations outside the intended Git repository's `.git` directory. The flaw stems from insufficient validation of reference paths during creation, renaming, and deletion operations. This can lead to the creation, overwriting, moving, or deletion of files, potentially compromising the application's integrity and availability. Applications that expose GitPython reference operations to user-controlled input are particularly vulnerable. This vulnerability was disclosed on 2026-05-06.

## Attack Chain

1.  An attacker identifies an application utilizing GitPython that exposes reference operations to user-controlled input.
2.  The attacker crafts a malicious reference path containing path traversal sequences like `../`.
3.  The attacker supplies the crafted reference path to the vulnerable GitPython API, such as `Reference.create` or `SymbolicReference.delete`.
4.  GitPython's API fails to adequately validate the reference path before constructing the file system path.
5.  The GitPython API uses the attacker-controlled path to interact with the file system outside the repository's `.git` directory.
6.  The attacker can now write arbitrary data to, overwrite existing data in, or delete files outside the Git repository, based on the initial API call.
7.  The attacker leverages the arbitrary file write/delete capabilities to corrupt application state, modify configuration files, or cause a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability can lead to several detrimental outcomes. An attacker could create or overwrite files outside the repository metadata directory, delete attacker-chosen files reachable from the process permissions, corrupt application state or configuration files, or cause a denial of service by deleting or overwriting critical files. This is especially concerning for applications like Git automation services, repository management backends, CI/CD helpers, and developer platforms. Multi-user environments where one user can influence ref names processed on behalf of another workflow are also at high risk.

## Recommendation

*   Upgrade GitPython to version 3.1.47 or later to incorporate the fix for CVE-2026-44243.
*   Implement input validation and sanitization on all user-supplied reference paths before passing them to GitPython APIs.
*   Deploy the Sigma rule `Detect GitPython Path Traversal File Creation` to identify attempts to create files outside the repository directory.
*   Deploy the Sigma rule `Detect GitPython Path Traversal File Deletion` to identify attempts to delete files outside the repository directory.
