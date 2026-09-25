---
title: Path Validation Bypass in gitoxide gix-fs
slug: 2026-09-gitoxide-path-bypass
description: The gitoxide gix-fs library before version 0.23.0 is vulnerable to a path validation bypass during worktree checkout that allows arbitrary file writes outside the intended directory via symlink manipulation.
date: "2026-09-25T22:55:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gitoxide:gix-fs:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - path-traversal
  - library-vulnerability
vendors:
  - gitoxide
products:
  - gix-fs (< 0.23.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: This can lead to arbitrary file manipulation or remote code execution when the library processes a malicious repository.
    confidence_band: high
cves:
  - id: CVE-2026-100419
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100419
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  mitigation_plan:
    - priority: immediate
      action: Upgrade gix-fs to version 0.23.0 or later
      owner: Development
      addresses: CVE-2026-100419
      evidence: NVD vulnerability disclosure for gitoxide gix-fs
---

The gitoxide gix-fs library, specifically versions prior to 0.23.0, contains a critical path validation bypass vulnerability within its worktree checkout mechanism. This vulnerability arises when the library performs a forced checkout with the 'overwrite_existing' configuration enabled. An attacker can create a specially crafted repository tree containing symlink entries designed to replace previously validated directories. During the checkout process, the library fails to adequately validate the target path of these symlinks, allowing the system to follow them and write subsequent files into arbitrary locations outside the designated worktree directory. This flaw presents a significant security risk, as it enables local file manipulation or potential code execution if an attacker can force a victim to clone or checkout a malicious repository using an affected version of the library.

## Impact

Successful exploitation of CVE-2026-100419 allows an attacker to overwrite arbitrary files on the host filesystem that the process running the gitoxide-based application has permission to modify. This can result in unauthorized file system access, modification of configuration files, or the planting of malicious scripts for subsequent execution. This affects any software or developer tool integrated with the gix-fs library prior to version 0.23.0.

## Recommendation

* Update all applications utilizing the gitoxide gix-fs crate to version 0.23.0 or later to remediate CVE-2026-100419.
* Audit build environments and CI/CD pipelines that pull and process untrusted Git repositories for the use of vulnerable library versions.
* Implement filesystem sandboxing or restrict process privileges for tools that execute git checkout operations on untrusted content.
