---
brief_id: brief-2026-11-20-git-lfs-ssh-cmd-exec-ghsa-w3f2-pr6x-wwjc
event_id: brief-2026-11-20-git-lfs-ssh-cmd-exec-ghsa-w3f2-pr6x-wwjc
revision: 1
activity_at: "2026-11-20T20:09:51Z"
title: 'Git LFS: Arbitrary command execution via crafted SSH URLs (CVE-2026-69260)'
slug: 2026-11-git-lfs-ssh-cmd-exec-ghsa-w3f2-pr6x-wwjc
description: Git LFS fails to correctly quote SSH URL path components, allowing attackers to inject shell meta-characters and achieve arbitrary command execution on remote hosts.
date: "2026-11-20T20:09:51Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:git_lfs:git_lfs:*:*:*:*:*:*:*:*
vendors:
  - Git LFS
products:
  - Git LFS
product_versions:
  - product: Git LFS
    range: '>= 0.5.0, <= 2.13.3'
  - product: Git LFS
    range: '>= 3.0.0, < 3.8.1'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Shell metacharacters in the SSH URL can therefore escape the intended path argument and cause arbitrary command execution when the remote Git LFS service passes received commands to a shell without adequate sanitization.
    confidence_band: high
cves:
  - id: CVE-2026-69260
    epss: 0.01101
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-w3f2-pr6x-wwjc
  - https://cveawg.mitre.org/api/cve/CVE-2026-69260
action_plan:
  priority: elevated
  hunt_leads:
    - lead: Identify command line execution strings originating from git-lfs that contain unusual shell metacharacters (e.g., semicolon, backticks, pipe symbols) within the remote SSH URL path components.
      technique_id: T1059
      data_needed:
        - Process execution logs
        - Command line arguments
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Shell metacharacters in the SSH URL can therefore escape the intended path argument and cause arbitrary command execution when the remote Git LFS service passes received commands to a shell without adequate sanitization.
  mitigation_plan:
    - priority: immediate
      action: Upgrade all instances of Git LFS to version 3.8.1 or later.
      evidence: This issue is fixed in version 3.8.1.
    - priority: short_term
      action: Set the Git configuration option `lfs.sshTransfer` to `never` for affected clients.
      evidence: Users may set the lfs.sshTransfer Git configuration option to never, after which Git LFS will not attempt any object transfers over SSH.
---

## Overview
Git LFS (v0.5.0 through 3.8.1) contains a vulnerability where the path component of an SSH URL is not properly formatted as a single argument when constructing remote object-transfer or authentication commands. Attackers can inject shell metacharacters into the SSH URL to escape the intended path argument. If the remote Git LFS service passes these commands to a shell without sufficient sanitization, it can result in arbitrary command execution. Additionally, Git LFS incorrectly encodes default HTTPS URLs when an SSH URL is configured and the remote host requires authentication but does not explicitly return an HTTP URL.

## Impact
Successful exploitation allows an attacker to execute arbitrary commands on a remote host that interfaces with the vulnerable Git LFS client. This impact is contingent upon the remote host's inability to sanitize commands received over SSH before execution.

## Recommendation
- Upgrade to Git LFS version 3.8.1 or later.
- As a temporary mitigation, set the Git configuration option `lfs.sshTransfer` to `never` to disable object transfers over SSH. Note that authentication requests to SSH URLs will still occur.
- Ensure all Git LFS service infrastructure sanitizes commands received over SSH before processing them.
