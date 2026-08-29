---
title: CVE-2026-82455 - Path Traversal in RubyGems Extraction Process
slug: 2026-08-rubygems-path-traversal
description: A path traversal vulnerability in RubyGems allows maliciously crafted gems to write files outside the intended extraction directory by exploiting improper symlink validation.
date: "2026-08-29T17:40:42Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rubygems:rubygems:*:*:*:*:*:*:*:*
vendors:
  - RubyGems
products:
  - RubyGems
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: A maliciously crafted gem can leverage a pre-existing symlink within the destination directory to escape the extraction root.
    confidence_band: high
cves:
  - id: CVE-2026-82455
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82455
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Update RubyGems software to the latest available version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-82455 requires version update for mitigation
  mitigation_plan:
    - priority: immediate
      action: Patch RubyGems environment
      owner: IT Operations
      addresses: CVE-2026-82455
      evidence: Source advisory confirms patch resolves extraction safety
---

RubyGems is vulnerable to a path traversal flaw during the gem extraction process, tracked as CVE-2026-82455. The vulnerability arises because RubyGems fails to re-validate path containment after resolving filesystem symlinks during package installation. An attacker can craft a malicious gem containing a symlink that points to a location outside the designated extraction root. If this symlink is placed within the destination directory, subsequent file extraction operations may follow the link, allowing the attacker to overwrite or create files in arbitrary locations on the host filesystem with the privileges of the user running the gem installation command. This could lead to remote code execution (RCE) if an attacker can overwrite critical system binaries, configuration files, or startup scripts. Defenders should update their RubyGems environments immediately to ensure proper path validation and symlink checks are enforced.

## Impact

The vulnerability allows for arbitrary file write on the host filesystem, potentially leading to privilege escalation or remote code execution. This impacts any user or CI/CD system that executes 'gem install' on untrusted or maliciously crafted gem files.

## Recommendation

* Update RubyGems to the patched version that incorporates the fix for CVE-2026-82455 to ensure that the real path of the parent directory is validated before file operations occur.
* Implement sandboxing or containerization for gem installation processes to limit the scope of potential file system access.
* Monitor build pipelines for unexpected file writes originating from gem installation processes.
